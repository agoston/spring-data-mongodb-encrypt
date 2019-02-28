package com.bol.crypt;

import org.bson.types.ObjectId;

public class DocumentCryptException extends RuntimeException {
    ObjectId id;
    String collectionName;

    public DocumentCryptException(String collectionName, ObjectId id, Throwable e) {
        super("Collection: " + collectionName + ", ObjectId: " + id, e);
        this.id = id;
        this.collectionName = collectionName;
    }

    public ObjectId getId() {
        return id;
    }

    public String getCollectionName() {
        return collectionName;
    }
}
