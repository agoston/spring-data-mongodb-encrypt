package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.reflection.Node;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.*;
import org.bson.types.Binary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.bol.reflection.ReflectionCache.processDocument;

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
        DBObject dbObject = event.getDBObject();

        Node node = encrypted.get(event.getType());
        if (node == null) return;

        cryptFields(dbObject, node, new Decoder()::apply);
    }

    private class Decoder extends BasicBSONDecoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] serialized = cryptVault.decrypt((byte[]) o);
            BSONCallback bsonCallback = new BasicDBObjectCallback();
            decode(serialized, bsonCallback);
            BSONObject deserialized = (BSONObject) bsonCallback.get();
            return deserialized.get("");
        }
    }

    /** BasicBSONEncoder returns BasicBSONObject which makes mongotemplate converter choke :( */
    private class BasicDBObjectCallback extends BasicBSONCallback {
        @Override
        public BSONObject create() {
            return new BasicDBObject();
        }

        @Override
        protected BSONObject createList() {
            return new BasicDBList();
        }

        @Override
        public BSONCallback createBSONCallback() {
            return new BasicDBObjectCallback();
        }
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        DBObject dbObject = event.getDBObject();

        Node node = encrypted.get(event.getSource().getClass());
        if (node == null) return;

        cryptFields(dbObject, node, new Encoder()::apply);
    }

    private class Encoder extends BasicBSONEncoder implements Function<Object, Object> {
        public Object apply(Object o) {
            // we need to put even BSONObject and BSONList in a wrapping object before serialization, otherwise the type information is not encoded.
            // this is not particularly effective, however, it is the same that mongo driver itself uses on the wire, so it has 100% compatibility w.r.t de/serialization
            byte[] serialized = encode(new BasicBSONObject("", o));
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
}
