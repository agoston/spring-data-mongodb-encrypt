package com.bol.system.model;

import com.bol.secure.Encrypted;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import static com.bol.system.model.RenamedField.MONGO_RENAMEDFIELD;

@Document(collection = MONGO_RENAMEDFIELD)
public class RenamedField {
    public static final String MONGO_RENAMEDFIELD = "renamedfield";
    public static final String MONGO_SOMESECRET = "someSecret";
    public static final String MONGO_NOTSECRET = "notSecret";
    public static final String MONGO_PASSWORD = "password";

    @Encrypted
    @Field("password")
    public String someSecret;
    public String notSecret;
}
