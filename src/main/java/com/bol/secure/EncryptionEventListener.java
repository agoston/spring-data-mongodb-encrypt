package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.reflection.Node;
import com.bol.util.JCEPolicy;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.BSONObject;
import org.bson.BasicBSONDecoder;
import org.bson.BasicBSONEncoder;
import org.bson.BasicBSONObject;
import org.bson.types.Binary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.mapping.BasicMongoPersistentEntity;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import javax.annotation.PostConstruct;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.util.*;
import java.util.function.Function;

import static com.bol.reflection.ReflectionCache.processDocument;
import static com.bol.util.Thrower.reThrow;

public class EncryptionEventListener extends AbstractMongoEventListener {
    Map<Class, Node> encrypted;

    @Autowired MongoMappingContext mappingContext;

    CryptVault cryptVault;

    public EncryptionEventListener(CryptVault cryptVault) {
        this.cryptVault = cryptVault;
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
        try {
            DBObject dbObject = event.getDBObject();

            Node node = encrypted.get(event.getType());
            if (node == null) return;

            cryptFields(dbObject, node, new Decoder()::apply);
        } catch (Exception e) {
            reThrow(e);
        }
    }

    private class Decoder extends BasicBSONDecoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] serialized = cryptVault.decrypt((byte[]) o);
            BSONObject bsonObject = readObject(serialized);
            Set<String> keys = bsonObject.keySet();
            if (keys.size() == 1 && keys.iterator().next().length() == 0) {
                return bsonObject.get("");
            }
            return bsonObject;
        }
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        try {
            DBObject dbObject = event.getDBObject();

            Node node = encrypted.get(event.getSource().getClass());
            if (node == null) return;

            cryptFields(dbObject, node, new Encoder()::apply);
        } catch (Exception e) {
            reThrow(e);
        }
    }

    private class Encoder extends BasicBSONEncoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] serialized;

            if (o instanceof BSONObject) {
                serialized = encode((BSONObject) o);
            } else {
                serialized = encode(new BasicBSONObject("", o));
            }

            return new Binary(cryptVault.encrypt(serialized));
        }
    }

    void cryptFields(DBObject dbObject, Node node, Function<Object, Object> crypt) {
        if (node.type == Node.Type.MAP) {
            Node mapChildren = node.children.get(0);
            for (Map.Entry<String, Object> entry : ((BasicDBObject) dbObject).entrySet()) {
                cryptFields((DBObject) entry.getValue(), mapChildren, crypt);
            }
            return;
        }

        for (Node childNode : node.children) {
            Object value = dbObject.get(childNode.fieldName);
            if (value == null) continue;

            if (!childNode.children.isEmpty()) {
                if (value instanceof BasicDBList) {
                    for (Object o : (BasicDBList) value)
                        cryptFields((DBObject) o, childNode, crypt);
                } else {
                    cryptFields((BasicDBObject) value, childNode, crypt);
                }
                return;
            }

            dbObject.put(childNode.fieldName, crypt.apply(value));
        }
    }

    static {
        // stupid JCE
        JCEPolicy.allowUnlimitedStrength();
    }
}
