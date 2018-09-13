package com.bol.system;

import org.springframework.data.mongodb.core.mapping.Field;

public class MySubBeanNotEncrypted {
    public static final String MONGO_NONSENSITIVEDATA1 = "nonSensitiveData1";
    public static final String MONGO_NONSENSITIVEDATA2 = "nonSensitiveData2";

    @Field
    public String nonSensitiveData1;

    @Field
    public String nonSensitiveData2;

    public MySubBeanNotEncrypted(String nonSensitiveData1, String nonSensitiveData2) {
        this.nonSensitiveData1 = nonSensitiveData1;
        this.nonSensitiveData2 = nonSensitiveData2;
    }
}
