package com.bol.system.model;

import com.bol.secure.Encrypted;

public class Identifier {
    @Encrypted
    public String someSecret;
    public String notSecret;
}
