package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.mongodb.BasicDBList;
import com.mongodb.DBObject;
import org.bson.types.BasicBSONList;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.Map;
import java.util.function.Function;

public class ReflectionEncryptionEventListener extends AbstractEncryptionEventListener {
    public ReflectionEncryptionEventListener(CryptVault cryptVault) {
        super(cryptVault);
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        DBObject dbObject = event.getDBObject();
        cryptFields(dbObject, event.getType(), new Decoder());
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        DBObject dbObject = event.getDBObject();
        cryptFields(dbObject, event.getSource().getClass(), new Encoder());
    }

    static void cryptFields(DBObject dbObject, Class node, Function<Object, Object> crypt) {
        for (String fieldName : dbObject.keySet()) {
            if (fieldName.equals("_class")) continue;

            Field field;
            try {
                field = node.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                continue;
            }

            if (field.isAnnotationPresent(Encrypted.class)) {
                // direct encryption
                Object value = dbObject.get(fieldName);
                dbObject.put(fieldName, crypt.apply(value));

            } else {

                Class<?> fieldType = field.getType();

                if (Collection.class.isAssignableFrom(fieldType)) {
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Type subFieldType = parameterizedType.getActualTypeArguments()[0];
                    BasicDBList list = (BasicDBList) dbObject.get(fieldName);
                    for (Object o : list) {
                        diveInto(crypt, (DBObject) o, subFieldType);
                    }

                } else if (Map.class.isAssignableFrom(fieldType)) {
                    ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
                    Type subFieldType = parameterizedType.getActualTypeArguments()[1];
                    DBObject map = (DBObject) dbObject.get(fieldName);
                    for (String key : map.keySet()) {
                        diveInto(crypt, (DBObject) map.get(key), subFieldType);
                    }
                } else {
                    Object o = dbObject.get(fieldName);
                    if (o instanceof DBObject) {
                        // descending into sub-documents
                        DBObject subObject = (DBObject) o;
                        diveInto(crypt, subObject, fieldType);

                    }
                    // otherwise, it's a primitive - ignore
                }
            }
        }
    }

    static void diveInto(Function<Object, Object> crypt, DBObject value, Type fieldType) {
        Class<?> childNode = fetchClassFromField(value);

        // fall back to reflection
        if (childNode == null) {
            if (fieldType instanceof Class) {
                childNode = (Class) fieldType;
                cryptFields(value, childNode, crypt);

            } else if (fieldType instanceof ParameterizedType) {
                ParameterizedType subType = (ParameterizedType) fieldType;
                Class rawType = (Class) subType.getRawType();

                if (Collection.class.isAssignableFrom(rawType)) {
                    Type subFieldType = subType.getActualTypeArguments()[0];
                    BasicDBList list = (BasicDBList) value;
                    for (Object o : list) diveInto(crypt, (DBObject) o, subFieldType);

                } else if (Map.class.isAssignableFrom(rawType)) {
                    Type subFieldType = subType.getActualTypeArguments()[1];
                    for (String key : value.keySet()) {
                        diveInto(crypt, (DBObject) value.get(key), subFieldType);
                    }

                } else throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass());

            } else throw new IllegalArgumentException("Unknown reflective type class " + fieldType.getClass());
        }
    }

    private static Class<?> fetchClassFromField(DBObject value) {
        // mongo-java-driver's basicbsonlist is one dirty hack :(
        if (value instanceof BasicBSONList) return null;

        String className = (String) value.get("_class");
        if (className != null) {
            try {
                return Class.forName(className);
            } catch (ClassNotFoundException ignored) { }
        }
        return null;
    }
}
