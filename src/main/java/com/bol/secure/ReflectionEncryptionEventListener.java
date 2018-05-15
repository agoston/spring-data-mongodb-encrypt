package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.bol.reflection.Node;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.springframework.data.mongodb.core.mapping.event.AfterLoadEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;

import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.List;
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

    void cryptFields(DBObject dbObject, Class node, Function<Object, Object> crypt) {
        for (String fieldName : dbObject.keySet()) {
            Field field;
            try {
                field = node.getField(fieldName);
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

                } else if (Map.class.isAssignableFrom(fieldType)) {

                } else {
                    // descending into sub-documents
                }
            }
        }
    }
}
