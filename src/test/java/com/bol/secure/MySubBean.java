package com.bol.secure;

import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Field;

public class MySubBean {
    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretData;
}
