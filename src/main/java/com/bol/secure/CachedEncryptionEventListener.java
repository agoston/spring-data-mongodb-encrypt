package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.crypt.DocumentCryptException;
import com.bol.crypt.FieldCryptException;
import com.bol.reflection.Node;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.mapping.BasicMongoPersistentEntity;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.bol.reflection.ReflectionCache.processDocument;

public class CachedEncryptionEventListener extends AbstractEncryptionEventListener<CachedEncryptionEventListener> {
    @Autowired MongoMappingContext mappingContext;

    HashMap<Class, Node> encrypted = new HashMap<>();

    public CachedEncryptionEventListener(CryptVault cryptVault) {
        super(cryptVault);
    }

    Node node(Class clazz) {
        return encrypted.computeIfAbsent(clazz, c -> {
            BasicMongoPersistentEntity<?> entity = mappingContext.getPersistentEntity(c);
            if (entity == null) return Node.EMPTY;

            List<Node> children = processDocument(entity.getType());
            if (!children.isEmpty()) return new Node("", children, Node.Type.ROOT);
            return Node.EMPTY;
        });
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        Document document = event.getDocument();

        Node node = node(event.getType());
        if (node == Node.EMPTY) return;

        try {
            cryptFields(document, node, new Decoder());
        } catch (Exception e) {
            ObjectId id = document.getObjectId("_id");
            throw new DocumentCryptException(event.getCollectionName(), id, e);
        }
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        Document document = event.getDocument();

        Node node = node(event.getSource().getClass());
        if (node == Node.EMPTY) return;

        try {
            cryptFields(document, node, new Encoder());
        } catch (Exception e) {
            ObjectId id = document.getObjectId("_id");
            throw new DocumentCryptException(event.getCollectionName(), id, e);
        }
    }

    void cryptFields(Object o, Node node, Function<Object, Object> crypt) {
        try {
            switch (node.type) {
                case MAP:
                    cryptMap((Document) o, node, crypt);
                    break;

                case DOCUMENT:
                case ROOT:
                    cryptDocument((Document) o, node, crypt);
                    break;

                case LIST:
                    cryptList((List) o, node, crypt);
                    break;

                default:
                    throw new IllegalArgumentException("Unknown class field to crypt for field " + node.fieldName + ": " + o.getClass());
            }
        } catch (ClassCastException e) {
            throw new FieldCryptException(node.fieldName, e);
        }
    }

    void cryptList(List list, Node node, Function<Object, Object> crypt) {
        if (node.type != Node.Type.LIST) throw new IllegalArgumentException("Expected list for " + node.fieldName + ", got " + node.type);

        Node mapChildren = node.children.get(0);
        for (int i = 0; i < list.size(); i++) {
            try {
                cryptFields(list.get(i), mapChildren, crypt);
            } catch (FieldCryptException e) {
                throw e.chain(Integer.toString(i));
            }
        }
    }

    void cryptMap(Document document, Node node, Function<Object, Object> crypt) {
        Node mapChildren = node.children.get(0);
        for (Map.Entry<String, Object> entry : document.entrySet()) {
            try {
                cryptFields(entry.getValue(), mapChildren, crypt);
            } catch (FieldCryptException e) {
                throw e.chain(entry.getKey());
            }
        }
    }

    void cryptDocument(Document document, Node node, Function<Object, Object> crypt) {
        for (Node childNode : node.children) {
            Object value = document.get(childNode.fieldName);
            if (value == null) continue;

            if (childNode.type == Node.Type.DIRECT) {
                try {
                    document.put(childNode.fieldName, crypt.apply(value));
                } catch (Exception e) {
                    throw new FieldCryptException(childNode.fieldName, e);
                }
            } else {
                try {
                    cryptFields(value, childNode, crypt);
                } catch (FieldCryptException e) {
                    throw e.chain(childNode.fieldName);
                }
            }
        }
    }
}
