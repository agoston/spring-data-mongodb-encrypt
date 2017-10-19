package com.bol.secure;

import java.security.Key;
import java.util.function.Function;

public class CryptVersion {
    final int saltLength;
    final String cipher;
    final Key key;
    final Function<Integer, Integer> encryptedLength;

    public CryptVersion(int saltLength, String cipher, Key key, Function<Integer, Integer> encryptedLength) {
        this.saltLength = saltLength;
        this.cipher = cipher;
        this.key = key;
        this.encryptedLength = encryptedLength;
    }
}
