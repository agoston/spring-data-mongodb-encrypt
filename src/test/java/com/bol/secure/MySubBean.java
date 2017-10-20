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
    /** this would cause infinite recursion in reflectioncache */
    public MyBean recursiveBean;

    public MySubBean() {}

    public MySubBean(String nonSensitiveData, String secretString) {
        this.nonSensitiveData = nonSensitiveData;
        this.secretString = secretString;
    }
}
