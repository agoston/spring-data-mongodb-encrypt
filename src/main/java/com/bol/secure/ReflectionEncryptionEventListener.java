package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.crypt.DocumentCryptException;
import com.bol.crypt.FieldCryptException;
import com.bol.reflection.Node;
import com.bol.reflection.ReflectionCache;
import org.bson.Document;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.bol.reflection.Node.Type.DIRECT;
import static com.bol.reflection.ReflectionCache.isPrimitive;

/**
 * This is a reimplementation of {@link CachedEncryptionEventListener}, to support polymorphism.
 * This means that while instead of walking by pre-cached class reflection, we have to walk by the Document provided and
 * try to match reflection data to it.
 */
public class ReflectionEncryptionEventListener extends AbstractEncryptionEventListener<ReflectionEncryptionEventListener> {
    public ReflectionEncryptionEventListener(CryptVault cryptVault) {
        super(cryptVault);
    }

    ReflectionCache reflectionCache = new ReflectionCache();

    void cryptDocument(Document document, Class clazz, Function<Object, Object> crypt) {
        List<Node> nodes = reflectionCache.reflectSingle(clazz);

        for (Map.Entry<String, Object> field : document.entrySet()) {
            String documentName = field.getKey();
            if (documentName.equals("_class")) continue;

            Node node = find(nodes, documentName);
            if (node == null) continue;

            Object fieldValue = field.getValue();

            if (node.type == DIRECT) {
                try {
                    document.put(documentName, crypt.apply(fieldValue));
                } catch (Exception e) {
                    throw new FieldCryptException(documentName, e);
                }

            } else {

                try {
                    diveInto(fieldValue, node.field.getGenericType(), crypt);
                } catch (FieldCryptException e) {
                    throw e.chain(documentName);
                }
            }
        }
    }

    void diveInto(Object value, Type type, Function<Object, Object> crypt) {
        // java primitive type; ignore
        if (isPrimitive(value.getClass())) return;

        Class reflectiveClass = null;
        Type[] typeArguments = null;
        if (type instanceof Class) reflectiveClass = (Class) type;
        else if (type instanceof ParameterizedType) {
            ParameterizedType parameterizedType = (ParameterizedType) type;
            Type rawType = parameterizedType.getRawType();
            typeArguments = parameterizedType.getActualTypeArguments();
            if (!(rawType instanceof Class)) throw new IllegalArgumentException("Unknown reflective type class " + type);
            reflectiveClass = (Class) rawType;
        } else throw new IllegalArgumentException("Unknown reflective type class " + type);

        if (value instanceof Document) {
            // Document could be a Map OR a Document; decide based on reflectiveClass
            if (Map.class.isAssignableFrom(reflectiveClass)) {
                Type subFieldType = typeArguments[1];

                for (Map.Entry entry : ((Map<?, ?>) value).entrySet()) {
                    try {
                        diveInto(entry.getValue(), subFieldType, crypt);
                    } catch (FieldCryptException e) {
                        throw e.chain(entry.getKey().toString());
                    }
                }

            } else {
                Class<?> childNode = fetchClassFromField((Document) value);
                if (childNode != null) {
                    cryptDocument((Document) value, childNode, crypt);
                } else {
                    cryptDocument((Document) value, reflectiveClass, crypt);
                }
            }
        } else if (value instanceof List) {
            if (Collection.class.isAssignableFrom(reflectiveClass)) {
                Type subFieldType = typeArguments[0];
                List list = (List) value;

                for (int i = 0; i < list.size(); i++) {
                    try {
                        diveInto(list.get(i), subFieldType, crypt);
                    } catch (FieldCryptException e) {
                        throw e.chain(Integer.toString(i));
                    }
                }

            } else {
                throw new IllegalArgumentException("Unknown reflective type class " + type.getClass());
            }
        } else {
            throw new IllegalArgumentException("Unknown reflective value class: " + value.getClass());
        }
    }

    private static Class<?> fetchClassFromField(Document value) {
        String className = (String) value.get("_class");
        if (className != null) {
            try {
                return Class.forName(className);
            } catch (ClassNotFoundException ignored) {
                throw new IllegalArgumentException("Unknown _class field reference: " + className);
            }
        }
        return null;
    }

    private static Node find(List<Node> nodes, String documentName) {
        for (Node node : nodes) {
            if (node.documentName.equals(documentName)) return node;
        }
        return null;
    }

    @Override
    public void onAfterLoad(AfterLoadEvent event) {
        Document document = event.getDocument();
        try {
            cryptDocument(document, event.getType(), new Decoder());
        } catch (Exception e) {
            Object id = document.get("_id");
            throw new DocumentCryptException(event.getCollectionName(), id, e);
        }
    }

    @Override
    public void onBeforeSave(BeforeSaveEvent event) {
        Document document = event.getDocument();
        try {
            cryptDocument(document, event.getSource().getClass(), new Encoder());
        } catch (Exception e) {
            Object id = document.get("_id");
            throw new DocumentCryptException(event.getCollectionName(), id, e);
        }
    }
}
