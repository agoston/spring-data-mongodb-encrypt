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

import static com.bol.reflection.Node.Type.*;

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
                    if (node.type == LIST) {
                        ParameterizedType parameterizedType = (ParameterizedType) node.field.getGenericType();
                        Type subFieldType = parameterizedType.getActualTypeArguments()[0];
                        List list = (List) fieldValue;
                        for (int i = 0; i < list.size(); i++) {
                            try {
                                diveInto(crypt, list.get(i), subFieldType);
                            } catch (FieldCryptException e) {
                                throw e.chain(Integer.toString(i));
                            }
                        }

                    } else if (node.type == MAP) {
                        ParameterizedType parameterizedType = (ParameterizedType) node.field.getGenericType();
                        Type subFieldType = parameterizedType.getActualTypeArguments()[1];
                        Document map = (Document) fieldValue;
                        for (Map.Entry<String, Object> entry : map.entrySet()) {
                            try {
                                diveInto(crypt, entry.getValue(), subFieldType);
                            } catch (FieldCryptException e) {
                                throw e.chain(entry.getKey());
                            }
                        }

                    } else if (fieldValue instanceof Document) {
                        // descending into sub-documents
                        Document subObject = (Document) fieldValue;
                        diveInto(crypt, subObject, node.field.getType());
                    }
                } catch (FieldCryptException e) {
                    throw e.chain(documentName);
                }
            }
        }
    }

    void diveInto(Function<Object, Object> crypt, Object value, Type fieldType) {
        if (value instanceof Document) {
            Class<?> childNode = fetchClassFromField((Document) value);
            if (childNode != null) {
                cryptDocument((Document) value, childNode, crypt);
                return;
            }

            // fall back to reflection
            if (fieldType instanceof Class) {
                childNode = (Class) fieldType;
                cryptDocument((Document) value, childNode, crypt);
            } else {
                throw new IllegalArgumentException("Unknown reflective type class " + fieldType);
            }
        } else if (value instanceof List) {
            if (fieldType instanceof ParameterizedType) {
                ParameterizedType subType = (ParameterizedType) fieldType;
                Class rawType = (Class) subType.getRawType();

                if (Collection.class.isAssignableFrom(rawType)) {
                    Type subFieldType = subType.getActualTypeArguments()[0];

                    for (Object o : (List) value)
                        diveInto(crypt, o, subFieldType);

                } else {
                    throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass() + "; should be Map<> or Collection<>");
                }
            } else {
                throw new IllegalArgumentException("Unknown reflective type class " + fieldType.getClass());
            }
        } else if (value instanceof Map) {
            if (fieldType instanceof ParameterizedType) {
                ParameterizedType subType = (ParameterizedType) fieldType;
                Class rawType = (Class) subType.getRawType();

                if (Map.class.isAssignableFrom(rawType)) {
                    Type subFieldType = subType.getActualTypeArguments()[0];

                    for (Object o : (List) value)
                        diveInto(crypt, o, subFieldType);

                } else {
                    throw new IllegalArgumentException("Unknown reflective raw type class " + rawType.getClass() + "; should be Map<> or Collection<>");
                }
            } else {
                throw new IllegalArgumentException("Unknown reflective type class " + fieldType.getClass());
            }


        } else if (value.getClass().getPackage().getName().equals("java.lang"))
            // primitive type, nothing to do here
            return;
        else
            throw new IllegalArgumentException("Unknown reflective value class: " + value.getClass());
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
