package com.bol.secure;

import org.springframework.data.mongodb.core.mapping.Field;

public class MySubBean {
    public static final String MONGO_NONSENSITIVEDATA = "nonSensitiveData";
    public static final String MONGO_SECRETSTRING = "secretString";

    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretString;

    @Field
    public MyBean recursiveBean;

    public MySubBean() {}

    public MySubBean(String nonSensitiveData, String secretString) {
        this.nonSensitiveData = nonSensitiveData;
        this.secretString = secretString;
    }
}
