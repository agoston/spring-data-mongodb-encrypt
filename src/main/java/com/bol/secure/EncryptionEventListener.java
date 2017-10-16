package com.bol.secure;

import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.BSONObject;
import org.bson.BasicBSONDecoder;
import org.bson.BasicBSONEncoder;
import org.bson.BasicBSONObject;
import org.bson.types.Binary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.mapping.BasicMongoPersistentEntity;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;
import org.springframework.scheduling.annotation.Scheduled;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Function;

// FIXME: key versioning
public class EncryptionEventListener extends AbstractMongoEventListener {
    private static final Logger LOG = LoggerFactory.getLogger(EncryptionEventListener.class);
    static final String MAP_FIELD_MATCHER = "*";

    static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    static final int DEFAULT_SALT_LENGTH = 16;

    final int saltLength;
    final String cipher;
    final SecretKeySpec key;

    Map<Class, Node> encrypted;

    public EncryptionEventListener(byte[] secret) {
        this(secret, DEFAULT_SALT_LENGTH, DEFAULT_CIPHER);
    }

    public EncryptionEventListener(byte[] secret, int saltLength) {
        this(secret, saltLength, DEFAULT_CIPHER);
    }

    public EncryptionEventListener(byte[] secret, int saltLength, String cipher) {
        this.saltLength = saltLength;
        this.cipher = cipher;
        this.key = new SecretKeySpec(secret, cipher.substring(0, cipher.indexOf('/')));
    }

    @Autowired MongoMappingContext mappingContext;

    @PostConstruct
    public void initReflection() {
        encrypted = new HashMap<>();

        for (BasicMongoPersistentEntity<?> entity : mappingContext.getPersistentEntities()) {
            List<Node> children = processDocument(entity.getType());
            if (!children.isEmpty()) encrypted.put(entity.getType(), new Node("", children, NodeType.ROOT));
        }
    }

    List<Node> processDocument(Class objectClass) {
        List<Node> nodes = new ArrayList<>();
        for (Field field : objectClass.getDeclaredFields()) {
            try {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) continue;
                if (!field.isAnnotationPresent(org.springframework.data.mongodb.core.mapping.Field.class)) continue;

                if (field.isAnnotationPresent(Encrypted.class)) {
                    // direct @Encrypted annotation - crypt the corresponding field of BasicDbObject
                    nodes.add(new Node(field.getName(), Collections.emptyList(), NodeType.DIRECT));

                } else if (Collection.class.isAssignableFrom(field.getType())) {
                    // descending into Collection
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];

                    List<Node> children = processDocument(genericClass);
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, NodeType.LIST));

                } else if (Map.class.isAssignableFrom(field.getType())) {
                    // descending into Values of Map objects
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Class<?> genericClass = (Class<?>) parameterizedType.getActualTypeArguments()[1];

                    List<Node> children = processDocument(genericClass);
                    if (!children.isEmpty()) {
                        List<Node> mapKeys = Collections.singletonList(new Node(MAP_FIELD_MATCHER, children, NodeType.DOCUMENT));
                        nodes.add(new Node(field.getName(), mapKeys, NodeType.MAP));
                    }

                } else {
                    // descending into sub-documents
                    List<Node> children = processDocument(field.getType());
                    if (!children.isEmpty()) nodes.add(new Node(field.getName(), children, NodeType.DOCUMENT));
                }

            } catch (Exception e) {
                LOG.error("{}.{}", objectClass.getName(), field.getName(), e);
            }
        }

        return nodes;
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        try {
            DBObject dbObject = event.getDBObject();

            Node node = encrypted.get(event.getType());
            if (node == null) return;

            cryptFields(dbObject, node, new Decoder()::apply);
        } catch (Exception e) {
            LOG.error("onAfterLoad", e);
            throw e;
        }
    }

    private class Decoder extends BasicBSONDecoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] serialized = decrypt((byte[]) o);
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
            LOG.error("onBeforeSave", e);
            throw e;
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

            return new Binary(encrypt(serialized));
        }
    }

    void cryptFields(DBObject dbObject, Node node, Function<Object, Object> crypt) {
        if (node.type == NodeType.MAP) {
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

    Cipher cipher() {
        try {
            return Cipher.getInstance(cipher);
        } catch (Exception e) {
            LOG.error("spring-data-mongodb-encrypt: init failed for cipher {}", cipher, e);
            return null;
        }
    }

    public SecureRandom SECURE_RANDOM = new SecureRandom();

    @Scheduled(initialDelay = 3_600_000, fixedDelay = 3_600_000)
    public void reinitSecureRandomHourly() {
        SECURE_RANDOM = new SecureRandom();
    }

    byte[] urandomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    byte[] encrypt(byte[] data) {
        try {
            byte[] random = urandomBytes(saltLength);
            IvParameterSpec iv_spec = new IvParameterSpec(random);
            Cipher cipher = cipher();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv_spec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            LOG.error("encrypt failed", e);
            return data;
        }
    }

    byte[] decrypt(byte[] data) {
        try {
            Cipher cipher = cipher();
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            LOG.error("decrypt failed", e);
            return data;
        }
    }

    class Node {
        public final String fieldName;
        public final List<Node> children;
        public final NodeType type;

        public Node(String fieldName, List<Node> children, NodeType type) {
            this.fieldName = fieldName;
            this.children = children;
            this.type = type;
        }
    }

    enum NodeType {
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
}
