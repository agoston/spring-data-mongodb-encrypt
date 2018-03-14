package com.bol.reflection;

import com.bol.secure.Encrypted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;
import java.util.stream.Collectors;

// fixme: unit test for preparing the model via reflection
public class ReflectionCache {

    private static final Logger LOG = LoggerFactory.getLogger(ReflectionCache.class);

    public static List<Node> processDocument(Class objectClass) {
        return processDocument(objectClass, new ArrayDeque<>());
    }

    static List<Node> processDocument(Class objectClass, Deque<Class> deque) {
        List<Node> nodes = new ArrayList<>();

        if (deque.contains(objectClass)) {
            LOG.error("cyclic reference found; " + objectClass.getName() + " is already mapped via " + deque.stream().map(s -> s.getName()).collect(Collectors.toList()));
            return nodes;
        }

        deque.addLast(objectClass);

        for (Field field : objectClass.getDeclaredFields()) {
            String fieldName = field.getName();
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) continue;
                if (!field.isAnnotationPresent(org.springframework.data.mongodb.core.mapping.Field.class)) continue;

                if (field.isAnnotationPresent(Encrypted.class)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(fieldName, Collections.emptyList(), Node.Type.DIRECT));

                } else {
                    Class<?> fieldType = field.getType();
                    Type fieldGenericType = field.getGenericType();

                    if (Collection.class.isAssignableFrom(fieldType)) {
                        // descending into Collection
                        ParameterizedType parameterizedType = (ParameterizedType) fieldGenericType;
                        Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];

                        List<Node> children = processDocument(genericClass, deque);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, children, Node.Type.LIST));

                    } else if (Map.class.isAssignableFrom(fieldType)) {
                        List<Node> children = processParameterizedTypes(fieldGenericType, deque);
//                        List<Node> children = processDocument(genericClass, deque);
                        if (!children.isEmpty()) {
                            List<Node> mapKeys = Collections.singletonList(new Node("*", children, Node.Type.DOCUMENT));
                            nodes.add(new Node(fieldName, mapKeys, Node.Type.MAP));
                        }

                    } else {
                        // descending into sub-documents
                        List<Node> children = processDocument(fieldType, deque);
                        if (!children.isEmpty()) nodes.add(new Node(fieldName, children, Node.Type.DOCUMENT));
                    }
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + fieldName, e);
            }
        }
        deque.removeLast();

        return nodes;
    }

    static List<Node> processParameterizedTypes(Type genericType, Deque<Class> deque) {
        ParameterizedType parameterizedType = (ParameterizedType) genericType;
        Type type = parameterizedType.getActualTypeArguments()[1];

        if (type instanceof Class) {
            return processDocument((Class)type, deque);
        } else if (type instanceof ParameterizedType) {
            throw new IllegalStateException();
        } else throw new IllegalArgumentException("Unknown reflective type class " + type.getClass());
    }
}
