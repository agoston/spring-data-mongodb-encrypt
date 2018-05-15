package com.bol.secure;

import com.bol.crypt.CryptVault;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import org.bson.*;
import org.bson.types.Binary;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;

import java.util.function.Function;

public class AbstractEncryptionEventListener extends AbstractMongoEventListener {
    protected CryptVault cryptVault;

    public AbstractEncryptionEventListener(CryptVault cryptVault) {
        this.cryptVault = cryptVault;
    }

    class Decoder extends BasicBSONDecoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] serialized = cryptVault.decrypt((byte[]) o);
            BSONCallback bsonCallback = new BasicDBObjectCallback();
            decode(serialized, bsonCallback);
            BSONObject deserialized = (BSONObject) bsonCallback.get();
            return deserialized.get("");
        }
    }

    /** BasicBSONEncoder returns BasicBSONObject which makes mongotemplate converter choke :( */
    class BasicDBObjectCallback extends BasicBSONCallback {
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

    class Encoder extends BasicBSONEncoder implements Function<Object, Object> {
        public Object apply(Object o) {
            // we need to put even BSONObject and BSONList in a wrapping object before serialization, otherwise the type information is not encoded.
            // this is not particularly effective, however, it is the same that mongo driver itself uses on the wire, so it has 100% compatibility w.r.t de/serialization
            byte[] serialized = encode(new BasicBSONObject("", o));
            return new Binary(cryptVault.encrypt(serialized));
        }
    }
}
