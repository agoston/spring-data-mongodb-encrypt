package com.bol.secure;

import com.bol.crypt.CryptOperationException;
import com.bol.crypt.CryptVault;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import org.bson.*;
import org.bson.types.Binary;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;

import java.util.function.Function;

public class AbstractEncryptionEventListener<T> extends AbstractMongoEventListener {
    protected CryptVault cryptVault;
    private boolean silentDecryptionFailure = false;

    public AbstractEncryptionEventListener(CryptVault cryptVault) {
        this.cryptVault = cryptVault;
    }

    public T withSilentDecryptionFailure(boolean silentDecryptionFailure) {
        this.silentDecryptionFailure = silentDecryptionFailure;
        return (T) this;
    }

    class Decoder extends BasicBSONDecoder implements Function<Object, Object> {
        public Object apply(Object o) {
            byte[] data;

            if (o instanceof Binary) data = ((Binary) o).getData();
            else if (o instanceof byte[]) data = (byte[]) o;
            else if (!silentDecryptionFailure) throw new IllegalStateException("Got " + o.getClass() + ", expected: Binary or byte[]");
            else return o;    // e.g. crypted field not encrypted, other issues - we do our best

            try {
                byte[] serialized = cryptVault.decrypt((data));
                BSONCallback bsonCallback = new BasicDBObjectCallback();
                decode(serialized, bsonCallback);
                BSONObject deserialized = (BSONObject) bsonCallback.get();
                return deserialized.get("");
            } catch (CryptOperationException e) {
                if (silentDecryptionFailure) return null;
                throw e;
            }
        }
    }

    /**
     * BasicBSONEncoder returns BasicBSONObject which makes mongotemplate converter choke :(
     */
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
