package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.reflection.Node;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
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

public class EncryptionEventListener extends AbstractEncryptionEventListener {
    @Autowired MongoMappingContext mappingContext;

    Map<Class, Node> encrypted;

    public EncryptionEventListener(CryptVault cryptVault) {
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
        DBObject dbObject = event.getDBObject();

        Node node = encrypted.get(event.getType());
        if (node == null) return;

        cryptFields(dbObject, node, new Decoder());
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        DBObject dbObject = event.getDBObject();

        Node node = encrypted.get(event.getSource().getClass());
        if (node == null) return;

        cryptFields(dbObject, node, new Encoder());
    }

    void cryptFields(DBObject dbObject, Node node, Function<Object, Object> crypt) {
        if (node.type == Node.Type.MAP) {
            Node mapChildren = node.children.get(0);
            for (Object entry : ((BasicDBObject) dbObject).values()) {
                cryptFields((DBObject) entry, mapChildren, crypt);
            }
            return;

        } else if (node.type == Node.Type.LIST) {
            Node mapChildren = node.children.get(0);
            for (Object entry : (BasicDBList) dbObject) {
                cryptFields((DBObject) entry, mapChildren, crypt);
            }
            return;
        }

        for (Node childNode : node.children) {
            Object value = dbObject.get(childNode.fieldName);
            if (value == null) continue;

            if (!childNode.children.isEmpty()) {
                if (value instanceof BasicDBList) {
                    for (Object o : (BasicDBList) value)
                        cryptFields((DBObject) o, childNode.children.get(0), crypt);
                } else {
                    cryptFields((BasicDBObject) value, childNode, crypt);
                }
                return;
            }

            dbObject.put(childNode.fieldName, crypt.apply(value));
        }
    }
}
