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

public class ReflectionCache {

    private static final Logger LOG = LoggerFactory.getLogger(ReflectionCache.class);

    private Map<Class, List<Node>> reflectionCache = new ConcurrentHashMap<>();

    // used by CachedEncryptionEventListener to gather metadata of a class and all it fields, recursively.
    public List<Node> reflectRecursive(Class objectClass) {
        List<Node> result = reflectionCache.get(objectClass);
        if (result != null) {
            LOG.trace("cyclic reference found; {} is already mapped", objectClass.getName());
            return result;
        }

        // java primitive type; ignore
        if (objectClass.getPackage().getName().equals("java.lang")) return Collections.emptyList();

        List<Node> nodes = new ArrayList<>();
        reflectionCache.put(objectClass, nodes);

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
                    Type fieldGenericType = field.getGenericType();

                    if (Collection.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, unwrap(children), Node.Type.LIST, field));

                    } else if (Map.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, unwrap(children), Node.Type.MAP, field));

                    } else {
                        // descending into sub-documents
                        List<Node> children = reflectRecursive(fieldType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, documentName, children, Node.Type.DOCUMENT, field));
                    }
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + fieldName, e);
            }
        });

        return nodes;
    }

    // used by ReflectionEncryptionEventListener to map a single Document
    public List<Node> reflectSingle(Class objectClass) {
        List<Node> result = reflectionCache.get(objectClass);
        if (result != null) {
            LOG.trace("cyclic reference found; {} is already mapped", objectClass.getName());
            return result;
        }

        // java primitive type; ignore
        if (objectClass.getPackage().getName().equals("java.lang")) return Collections.emptyList();

        List<Node> nodes = new ArrayList<>();
        reflectionCache.put(objectClass, nodes);

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
                    Type fieldGenericType = field.getGenericType();

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

    List<Node> processParameterizedTypes(Type type) {
        if (type instanceof Class) {
            List<Node> children = reflectRecursive((Class) type);
            if (!children.isEmpty()) return Collections.singletonList(new Node(null, children, Node.Type.DOCUMENT));

        } else if (type instanceof ParameterizedType) {
            ParameterizedType subType = (ParameterizedType) type;
            Class rawType = (Class) subType.getRawType();

            if (Collection.class.isAssignableFrom(rawType)) {
                List<Node> children = processParameterizedTypes(subType.getActualTypeArguments()[0]);
                if (!children.isEmpty()) return Collections.singletonList(new Node(null, children, Node.Type.LIST));

            } else if (Map.class.isAssignableFrom(rawType)) {
                List<Node> children = processParameterizedTypes(subType.getActualTypeArguments()[1]);
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
}
