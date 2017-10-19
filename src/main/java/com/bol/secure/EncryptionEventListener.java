package com.bol.secure;

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
import org.springframework.scheduling.annotation.Scheduled;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Function;

import static com.bol.util.Thrower.reThrow;

public class EncryptionEventListener extends AbstractMongoEventListener {
    static final String MAP_FIELD_MATCHER = "*";

    static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    static final String DEFAULT_ALGORITHM = "AES";
    static final int DEFAULT_SALT_LENGTH = 16;

    CryptVersion[] cryptVersions = new CryptVersion[256];
    int defaultVersion = -1;

    Map<Class, Node> encrypted;

    @Autowired MongoMappingContext mappingContext;

    /**
     * Helper method for the most used case.
     * If you even need to change this, or need backwards compatibility, use the more advanced constructor instead.
     */
    public EncryptionEventListener with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(int version, byte[] secret) {
        if (secret.length != 32) throw new IllegalArgumentException("invalid AES key size; should be 256 bits!");

        Key key = new SecretKeySpec(secret, DEFAULT_ALGORITHM);
        CryptVersion cryptVersion = new CryptVersion(DEFAULT_SALT_LENGTH, DEFAULT_CIPHER, key, AESLengthCalculator);
        return withKey(version, cryptVersion);
    }

    public EncryptionEventListener withKey(int version, CryptVersion cryptVersion) {
        if (version < 0 || version > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[version] != null) throw new IllegalArgumentException("version " + version + " is already defined");

        cryptVersions[version] = cryptVersion;
        if (version > defaultVersion) defaultVersion = version;
        return this;
    }

    /** specifies the version used in encrypting new data. default is highest version number. */
    public EncryptionEventListener withDefaultKeyVersion(int defaultVersion) {
        if (defaultVersion < 0 || defaultVersion > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[defaultVersion] == null) throw new IllegalArgumentException("version " + defaultVersion + " is undefined");

        this.defaultVersion = defaultVersion;
        return this;
    }

    @PostConstruct
    public void initReflection() {
        encrypted = new HashMap<>();

        for (BasicMongoPersistentEntity<?> entity : mappingContext.getPersistentEntities()) {
            List<Node> children = processDocument(entity.getType());
            if (!children.isEmpty()) encrypted.put(entity.getType(), new Node("", children, NodeType.ROOT));
        }
    }

    static {
        // stupid JCE
        JCEPolicy.allowUnlimitedStrength();
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
                throw new IllegalArgumentException(objectClass.getName() + "." + field.getName(), e);
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
            reThrow(e);
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

            return new Binary(encrypt(defaultVersion, serialized));
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

    // FIXME: have a pool of ciphers (with locks & so), cipher init seems to be very costly (jmh it!)
    Cipher cipher(String cipher) {
        try {
            return Cipher.getInstance(cipher);
        } catch (Exception e) {
            throw new IllegalStateException("spring-data-mongodb-encrypt: init failed for cipher " + cipher, e);
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

    byte[] encrypt(int version, byte[] data) {
        CryptVersion cryptVersion = cryptVersion(version);
        try {
            int cryptedLength = cryptVersion.encryptedLength.apply(data.length);
            byte[] result = new byte[cryptedLength + cryptVersion.saltLength + 1];
            result[0] = toSignedByte(version);

            byte[] random = urandomBytes(cryptVersion.saltLength);
            IvParameterSpec iv_spec = new IvParameterSpec(random);
            System.arraycopy(random, 0, result, 1, cryptVersion.saltLength);

            Cipher cipher = cipher(cryptVersion.cipher);
            cipher.init(Cipher.ENCRYPT_MODE, cryptVersion.key, iv_spec);
            int len = cipher.doFinal(data, 0, data.length, result, cryptVersion.saltLength + 1);

            // fixme remove
            if (len != cryptedLength) System.err.println("len was " + len + " instead of " + cryptedLength);

            return result;
        } catch (Exception e) {
            return reThrow(e);
        }
    }

    byte[] decrypt(byte[] data) {
        int version = fromSignedByte(data[0]);
        CryptVersion cryptVersion = cryptVersion(version);

        try {
            byte[] random = new byte[cryptVersion.saltLength];
            System.arraycopy(data, 1, random, 0, cryptVersion.saltLength);
            IvParameterSpec iv_spec = new IvParameterSpec(random);

            Cipher cipher = cipher(cryptVersions[version].cipher);
            cipher.init(Cipher.DECRYPT_MODE, cryptVersions[version].key, iv_spec);
            return cipher.doFinal(data, cryptVersion.saltLength + 1, data.length - cryptVersion.saltLength - 1);
        } catch (Exception e) {
            return reThrow(e);
        }
    }

    private CryptVersion cryptVersion(int version) {
        try {
            CryptVersion result = cryptVersions[version];
            if (result == null) throw new IllegalArgumentException("version " + version + " undefined");
            return result;
        } catch (IndexOutOfBoundsException e) {
            if (version < 0) throw new IllegalStateException("encryption keys are not initialized");
            throw new IllegalArgumentException("version must be a byte (0-255)");
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

    /** AES simply pads to next 128 bits & has to be at least 32 bytes long */
    static final Function<Integer, Integer> AESLengthCalculator = i -> Math.max(i | 0xf, 32);

    /** because, you know... java */
    static byte toSignedByte(int val) {
        return (byte) (val + Byte.MIN_VALUE);
    }

    /** because, you know... java */
    static int fromSignedByte(byte val) {
        return ((int) val - Byte.MIN_VALUE);
    }
}
