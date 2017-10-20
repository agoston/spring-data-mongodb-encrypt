package com.bol.reflection;

import com.bol.secure.Encrypted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.util.*;

// fixme: unit test for preparing the model via reflection
public class ReflectionCache {

    private static final Logger LOG = LoggerFactory.getLogger(ReflectionCache.class);

    public static List<Node> processDocument(Class objectClass) {
        return processDocument(objectClass, new ArrayDeque<>());
    }

    static List<Node> processDocument(Class objectClass, Deque<Class> deque) {
        List<Node> nodes = new ArrayList<>();

        if (deque.contains(objectClass)) {
            LOG.error("cyclic reference found; " + objectClass.getName() + " is already mapped via " + deque.stream().map(s -> s.getName()));
            return nodes;
        }

        deque.addLast(objectClass);

        for (Field field : objectClass.getDeclaredFields()) {
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) continue;
                if (!field.isAnnotationPresent(org.springframework.data.mongodb.core.mapping.Field.class)) continue;

                if (field.isAnnotationPresent(Encrypted.class)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(field.getName(), Collections.emptyList(), Node.Type.DIRECT));

                } else if (Collection.class.isAssignableFrom(field.getType())) {
                    // descending into Collection
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];

                    List<Node> children = processDocument(genericClass, deque);
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, Node.Type.LIST));

                } else if (Map.class.isAssignableFrom(field.getType())) {
                    // descending into Values of Map objects
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[1];

                    List<Node> children = processDocument(genericClass, deque);
                    if (!children.isEmpty()) {
                        List<Node> mapKeys = Collections.singletonList(new Node("*", children, Node.Type.DOCUMENT));
                        nodes.add(new Node(field.getName(), mapKeys, Node.Type.MAP));
                    }

                } else {
                    // descending into sub-documents
                    List<Node> children = processDocument(field.getType(), deque);
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, Node.Type.DOCUMENT));
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + field.getName(), e);
            }
        }
        deque.removeLast();

        return nodes;
    }

}
