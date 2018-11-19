package com.bol.crypt;

public class CryptOperationException extends RuntimeException {
    public CryptOperationException(String s, Throwable e) {
        super(s, e);
    }
}
