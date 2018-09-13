package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.reflection.Node;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.bol.reflection.ReflectionCache.processDocument;

public class CachedEncryptionEventListener extends AbstractEncryptionEventListener {
    @Autowired
    MongoMappingContext mappingContext;

    Map<Class, Node> encrypted;

    public CachedEncryptionEventListener(CryptVault cryptVault) {
        super(cryptVault);
    }

    @PostConstruct
    public void initReflection() {
        encrypted = new HashMap<>();

        mappingContext.getPersistentEntities().forEach(entity -> {
            List<Node> children = processDocument(entity.getType());
            if (!children.isEmpty()) encrypted.put(entity.getType(), new Node("", children, Node.Type.ROOT));
        });
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        Document document = event.getDocument();

        Node node = encrypted.get(event.getType());
        if (node == null) return;

        cryptFields(document, node, new Decoder());
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        Document document = event.getDocument();

        Node node = encrypted.get(event.getSource().getClass());
        if (node == null) return;

        cryptFields(document, node, new Encoder());
    }


    void cryptFields(Object o, Node node, Function<Object, Object> crypt) {
        if (o instanceof Document) {
            cryptField((Document) o, node, crypt);
        } else if (o instanceof List) {
            cryptField((List) o, node, crypt);
        } else {
            throw new IllegalArgumentException("Unknown class field to crypt " + o.getClass());
        }
    }

    void cryptField(List list, Node node, Function<Object, Object> crypt) {
        if (node.type == Node.Type.LIST) {

            Node mapChildren = node.children.get(0);
            for (Object entry : list) {
                cryptFields(entry, mapChildren, crypt);
            }
            return;
        } else {
            throw new IllegalArgumentException("Unmatching node type for a List object " + node.type);
        }
    }


    void cryptField(Document document, Node node, Function<Object, Object> crypt) {
        if (node.type == Node.Type.MAP) {

            Node mapChildren = node.children.get(0);
            for (Object entry : document.values()) {

                cryptFields(entry, mapChildren, crypt);
            }
            return;

        }
        for (Node childNode : node.children) {
            Object value = document.get(childNode.fieldName);

            if (value == null) continue;

            if (!childNode.children.isEmpty()) {
                if (value instanceof List) {
                    for (Object o : (List) value) {
                        cryptFields(o, childNode.children.get(0), crypt);
                    }
                } else {
                    cryptFields(value, childNode, crypt);
                }
                return;
            }

            document.put(childNode.fieldName, crypt.apply(value));
        }
    }

}
