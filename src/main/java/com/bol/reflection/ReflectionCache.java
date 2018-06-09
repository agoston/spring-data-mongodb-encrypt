package com.bol.reflection;

import com.bol.secure.Encrypted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;

public class ReflectionCache {

    private static final Logger LOG = LoggerFactory.getLogger(ReflectionCache.class);

    private static Map<Class, List<Node>> cyclicClassReference = new HashMap<>();

    public static List<Node> processDocument(Class objectClass) {
        List<Node> result = cyclicClassReference.get(objectClass);
        if (result != null) {
            LOG.info("cyclic reference found; " + objectClass.getName() + " is already mapped");
            return result;
        }

        List<Node> nodes = new ArrayList<>();
        cyclicClassReference.put(objectClass, nodes);

        ReflectionUtils.doWithFields(objectClass, field -> {
            String fieldName = field.getName();
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) return;

                if (field.isAnnotationPresent(Encrypted.class)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(fieldName, Collections.emptyList(), Node.Type.DIRECT));

                } else {
                    Class<?> fieldType = field.getType();
                    Type fieldGenericType = field.getGenericType();

                    if (Collection.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, unwrap(children), Node.Type.LIST));

                    } else if (Map.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, unwrap(children), Node.Type.MAP));

                    } else {
                        // descending into sub-documents
                        List<Node> children = processDocument(fieldType);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, children, Node.Type.DOCUMENT));
                    }
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + fieldName, e);
            }
        });

        return nodes;
    }

    static List<Node> processParameterizedTypes(Type type) {
        if (type instanceof Class) {
            List<Node> children = processDocument((Class) type);
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

            } else throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass());

        } else throw new IllegalArgumentException("Unknown reflective type class " + type.getClass());
        return Collections.emptyList();
    }

    static List<Node> unwrap(List<Node> result) {
        if (result.size() != 1) return result;
        Node node = result.get(0);
        if (node.fieldName != null) return result;
        return node.children;
    }
}
