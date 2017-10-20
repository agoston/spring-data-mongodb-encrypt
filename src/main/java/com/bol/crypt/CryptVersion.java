package com.bol.crypt;

import java.security.Key;
import java.util.function.Function;

/** Immutable data class */
public class CryptVersion {
    public final int saltLength;
    public final String cipher;
    public final Key key;
    public final Function<Integer, Integer> encryptedLength;

    public CryptVersion(int saltLength, String cipher, Key key, Function<Integer, Integer> encryptedLength) {
        this.saltLength = saltLength;
        this.cipher = cipher;
        this.key = key;
        this.encryptedLength = encryptedLength;
    }
}
