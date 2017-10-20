package com.bol.secure;

import org.assertj.core.util.VisibleForTesting;
import org.springframework.data.mongodb.core.mapping.Field;

public class MySubBean {
    public static final String MONGO_NONSENSITIVEDATA = "nonSensitiveData";
    public static final String MONGO_SECRETSTRING = "secretString";

    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretString;

    public MySubBean() {}

    public MySubBean(String nonSensitiveData, String secretString) {
        this.nonSensitiveData = nonSensitiveData;
        this.secretString = secretString;
    }
}
