package com.bol.secure;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "mybean")
public class MyBean {
    @Id
    public String id;

    @Field
    public String nonSensitiveData;

    @Field
    @Version
    public Long version;
}
