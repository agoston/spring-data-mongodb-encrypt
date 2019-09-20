package com.bol.reflection;

import java.util.List;

public class Node {
    public final String fieldName;
    public final List<Node> children;
    public final Type type;

    public Node(String fieldName, List<Node> children, Type type) {
        this.fieldName = fieldName;
        this.children = children;
        this.type = type;
    }

    public enum Type {
        /** root node, on @Document classes */
        ROOT,
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
