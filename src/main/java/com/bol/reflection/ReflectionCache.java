package com.bol.reflection;

import com.bol.secure.Encrypted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.bol.reflection.FieldEncryptedPredicate.ANNOTATION_PRESENT;

public class ReflectionCache {

    private static final Logger LOG = LoggerFactory.getLogger(ReflectionCache.class);

    private final ConcurrentHashMap<Class, List<Node>> reflectionCache = new ConcurrentHashMap<>();

    private final FieldEncryptedPredicate fieldEncryptedPredicate;

    public ReflectionCache() {
        this(ANNOTATION_PRESENT);
    }

    public ReflectionCache(FieldEncryptedPredicate fieldEncryptedPredicate) {
        this.fieldEncryptedPredicate = fieldEncryptedPredicate;
    }

    // used by CachedEncryptionEventListener to gather metadata of a class and all it fields, recursively.
    public List<Node> reflectRecursive(Class objectClass) {
        List<Node> nodes = reflectionCache.get(objectClass);
        if (nodes != null) return nodes;

        synchronized (this) {
            return buildRecursive(objectClass, new HashMap<>());
        }
    }

    // building is necessary to avoid putting half-processed data in `reflectionCache` (where it would be returned to other threads)
    private List<Node> buildRecursive(Class objectClass, HashMap<Class, List<Node>> building) {
        if (isPrimitive(objectClass)) return Collections.emptyList();

        List<Node> processed = reflectionCache.get(objectClass);
        if (processed != null) return processed;

        List<Node> processing = building.get(objectClass);
        if (processing != null) return processing;

        List<Node> nodes = new ArrayList<>();
        building.put(objectClass, nodes);

        ReflectionUtils.doWithFields(objectClass, field -> {
            String fieldName = field.getName();
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) return;

                String documentName = parseFieldAnnotation(field, fieldName);

                if (fieldEncryptedPredicate.test(field)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(fieldName, documentName, Collections.emptyList(), Node.Type.DIRECT, field));

                } else {
                    Class<?> fieldType = field.getType();
                    Type fieldGenericType = field.getGenericType();

                    if (Collection.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType, building);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, unwrap(children), Node.Type.LIST, field));

                    } else if (Map.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType, building);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, unwrap(children), Node.Type.MAP, field));

                    } else {
                        // descending into sub-documents
                        List<Node> children = buildRecursive(fieldType, building);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, children, Node.Type.DOCUMENT, field));
                    }
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + fieldName, e);
            }
        });

        reflectionCache.put(objectClass, nodes);

        return nodes;
    }

    // used by ReflectionEncryptionEventListener to map a single Document
    public List<Node> reflectSingle(Class objectClass) {
        return reflectionCache.computeIfAbsent(objectClass, this::buildSingle);
    }

    // FIXME: this is a slimmed down copy-paste of buildRecursive(); find a way to bring Cached and Reflective listener closer together!
    private List<Node> buildSingle(Class objectClass) {
        if (isPrimitive(objectClass)) return Collections.emptyList();

        List<Node> nodes = new ArrayList<>();

        ReflectionUtils.doWithFields(objectClass, field -> {
            String fieldName = field.getName();
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) return;

                String documentName = parseFieldAnnotation(field, fieldName);

                if (field.isAnnotationPresent(Encrypted.class)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(fieldName, documentName, Collections.emptyList(), Node.Type.DIRECT, field));

                } else {
                    Class<?> fieldType = field.getType();

                    if (Collection.class.isAssignableFrom(fieldType)) {
                        nodes.add(new Node(fieldName, documentName, Collections.emptyList(), Node.Type.LIST, field));

                    } else if (Map.class.isAssignableFrom(fieldType)) {
                        nodes.add(new Node(fieldName, documentName, Collections.emptyList(), Node.Type.MAP, field));

                    } else {
                        nodes.add(new Node(fieldName, documentName, Collections.emptyList(), Node.Type.DOCUMENT, field));
                    }
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + fieldName, e);
            }
        });

        return nodes;
    }

    List<Node> processParameterizedTypes(Type type, HashMap<Class, List<Node>> building) {
        if (type instanceof Class) {
            List<Node> children = buildRecursive((Class) type, building);
            if (!children.isEmpty()) return Collections.singletonList(new Node(null, children, Node.Type.DOCUMENT));

        } else if (type instanceof ParameterizedType) {
            ParameterizedType subType = (ParameterizedType) type;
            Class rawType = (Class) subType.getRawType();

            if (Collection.class.isAssignableFrom(rawType)) {
                List<Node> children = processParameterizedTypes(subType.getActualTypeArguments()[0], building);
                if (!children.isEmpty()) return Collections.singletonList(new Node(null, children, Node.Type.LIST));

            } else if (Map.class.isAssignableFrom(rawType)) {
                List<Node> children = processParameterizedTypes(subType.getActualTypeArguments()[1], building);
                if (!children.isEmpty()) return Collections.singletonList(new Node(null, children, Node.Type.MAP));

            } else {
                throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass());
            }

        } else {
            throw new IllegalArgumentException("Unknown reflective type class " + type.getClass());
        }

        return Collections.emptyList();
    }

    static List<Node> unwrap(List<Node> result) {
        if (result.size() != 1) return result;
        Node node = result.get(0);
        if (node.fieldName != null) return result;
        return node.children;
    }

    /**
     * process custom name in @Field annotation
     */
    static String parseFieldAnnotation(java.lang.reflect.Field field, String fieldName) {
        Field fieldAnnotation = field.getAnnotation(Field.class);
        if (fieldAnnotation != null) {
            String name = fieldAnnotation.name();

            if (!name.isEmpty()) return name;
            else {
                String value = fieldAnnotation.value();
                if (!value.isEmpty()) return value;
            }
        }
        return fieldName;
    }

    // same as ClassUtils.isPrimitiveOrWrapper(), but also includes String
    public static boolean isPrimitive(Class clazz) {
        return clazz.isPrimitive() || primitiveClasses.contains(clazz);
    }

    private static Set<Class> primitiveClasses = new HashSet<>();

    static {
        primitiveClasses.add(Boolean.class);
        primitiveClasses.add(Byte.class);
        primitiveClasses.add(Character.class);
        primitiveClasses.add(Double.class);
        primitiveClasses.add(Float.class);
        primitiveClasses.add(Integer.class);
        primitiveClasses.add(Long.class);
        primitiveClasses.add(Short.class);
        primitiveClasses.add(Void.class);
        primitiveClasses.add(String.class);
    }
}
