package com.bol.reflection;

import java.lang.reflect.Field;
import java.util.List;

public class Node {
    public final String fieldName;
    public final String documentName;
    public final List<Node> children;
    public final Type type;
    public final Field field;

    public Node(String fieldName, List<Node> children, Type type) {
        this.fieldName = fieldName;
        this.documentName = fieldName;
        this.children = children;
        this.type = type;
        this.field = null;
    }

    public Node(String fieldName, String documentName, List<Node> children, Type type) {
        this.fieldName = fieldName;
        this.documentName = documentName;
        this.children = children;
        this.type = type;
        this.field = null;
    }

    public Node(String fieldName, String documentName, List<Node> children, Type type, Field field) {
        this.fieldName = fieldName;
        this.documentName = documentName;
        this.children = children;
        this.type = type;
        this.field = field;
    }

    public enum Type {
        /** field with @Encrypted annotation present - to be crypted directly */
        DIRECT,
        /** field is a BasicDBList, descend */
        LIST,
        /** field is a Map, need to descend on its values */
        MAP,
        /** field is a sub-document, descend */
        DOCUMENT
    }

    public static final Node EMPTY = new Node(null, null, null);
}
