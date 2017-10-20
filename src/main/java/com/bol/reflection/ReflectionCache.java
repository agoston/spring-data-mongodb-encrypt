package com.bol.reflection;

import com.bol.secure.Encrypted;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.util.*;

// fixme: unit test for preparing the model via reflection
public class ReflectionCache {
    public static List<Node> processDocument(Class objectClass) {
        List<Node> nodes = new ArrayList<>();
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

                    List<Node> children = processDocument(genericClass);
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, Node.Type.LIST));

                } else if (Map.class.isAssignableFrom(field.getType())) {
                    // descending into Values of Map objects
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[1];

                    List<Node> children = processDocument(genericClass);
                    if (!children.isEmpty()) {
                        List<Node> mapKeys = Collections.singletonList(new Node("*", children, Node.Type.DOCUMENT));
                        nodes.add(new Node(field.getName(), mapKeys, Node.Type.MAP));
                    }

                } else {
                    // descending into sub-documents
                    List<Node> children = processDocument(field.getType());
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, Node.Type.DOCUMENT));
                }

            } catch (Exception e) {
                throw new IllegalArgumentException(objectClass.getName() + "." + field.getName(), e);
            }
        }

        return nodes;
    }

}
