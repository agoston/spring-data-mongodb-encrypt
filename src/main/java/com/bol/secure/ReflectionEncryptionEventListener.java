package com.bol.secure;

import com.bol.crypt.CryptVault;
import org.bson.Document;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class ReflectionEncryptionEventListener extends AbstractEncryptionEventListener {
    public ReflectionEncryptionEventListener(CryptVault cryptVault) {
        super(cryptVault);
    }

    static void cryptFields(Document document, Class node, Function<Object, Object> crypt) {
        for (Map.Entry<String, Object> field : document.entrySet()) {
            String fieldName = field.getKey();
            if (fieldName.equals("_class")) continue;

            Field classField = ReflectionUtils.findField(node, fieldName);
            if (classField == null) continue;

            Object fieldValue = field.getValue();

            if (classField.isAnnotationPresent(Encrypted.class)) {
                // direct encryption
                document.put(fieldName, crypt.apply(fieldValue));

            } else {

                if (Collection.class.isAssignableFrom(classField.getType())) {
                    ParameterizedType parameterizedType = (ParameterizedType) classField.getGenericType();
                    Type subFieldType = parameterizedType.getActualTypeArguments()[0];
                    ArrayList list = (ArrayList) fieldValue;
                    for (Object o : list) {
                        diveIntoGeneric(crypt, o, subFieldType);
                    }

                } else if (Map.class.isAssignableFrom(classField.getType())) {
                    ParameterizedType parameterizedType = (ParameterizedType) classField.getGenericType();
                    Type subFieldType = parameterizedType.getActualTypeArguments()[1];
                    Document map = (Document) fieldValue;
                    for (String key : map.keySet()) {
                        diveIntoGeneric(crypt, map.get(key), subFieldType);
                    }
                } else {
                    if (fieldValue instanceof Document) {
                        // descending into sub-documents
                        Document subObject = (Document) fieldValue;
                        diveIntoGeneric(crypt, subObject, classField.getType());
                    }
                }
            }
        }
    }


    static void diveIntoGeneric(Function<Object, Object> crypt, Object value, Type fieldType) {
        if (value instanceof Document)
            diveInto(crypt, (Document) value, fieldType);
        else if (value instanceof List)
            diveInto(crypt, (List) value, fieldType);
        else
            throw new IllegalArgumentException("Unknown reflective value class " + value.getClass());
    }


    static void diveInto(Function<Object, Object> crypt, Document value, Type fieldType) {
        Class<?> childNode = fetchClassFromField(value);
        if (childNode != null) {
            cryptFields(value, childNode, crypt);
            return;
        }

        // fall back to reflection
        if (fieldType instanceof Class) {
            childNode = (Class) fieldType;
            cryptFields(value, childNode, crypt);
        } else {
            throw new IllegalArgumentException("Unknown reflective type class " + fieldType.getClass());
        }
    }

    static void diveInto(Function<Object, Object> crypt, List value, Type fieldType) {
        if (fieldType instanceof ParameterizedType) {
            ParameterizedType subType = (ParameterizedType) fieldType;
            Class rawType = (Class) subType.getRawType();

            if (Collection.class.isAssignableFrom(rawType)) {
                Type subFieldType = subType.getActualTypeArguments()[0];

                for (Object o : value)
                    diveIntoGeneric(crypt, o, subFieldType);

            } else {
                throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass() + "; should be Map<> or Collection<>");
            }
        } else {
            throw new IllegalArgumentException("Unknown reflective type class " + fieldType.getClass());
        }
    }

    private static Class<?> fetchClassFromField(Document value) {
        String className = (String) value.get("_class");
        if (className != null) {
            try {
                return Class.forName(className);
            } catch (ClassNotFoundException ignored) {
            }
        }
        return null;
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        Document document = event.getDocument();
        cryptFields(document, event.getType(), new Decoder());
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        Document document = event.getDocument();
        cryptFields(document, event.getSource().getClass(), new Encoder());

    }
}
