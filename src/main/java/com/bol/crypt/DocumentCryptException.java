package com.bol.crypt;

public class DocumentCryptException extends RuntimeException {
    Object id;
    String collectionName;

    public DocumentCryptException(String collectionName, Object id, Throwable e) {
        super("Collection: " + collectionName + ", Id: " + id, e);
        this.id = id;
        this.collectionName = collectionName;
    }

    public Object getId() {
        return id;
    }

    public String getCollectionName() {
        return collectionName;
    }
}
