package com.bol.secure;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = MyBean.MONGO_MYBEAN)
public class MyBean {
    public static final String MONGO_MYBEAN = "mybean";
    public static final String MONGO_SECRETDATA = "secretData";

    @Id
    public String id;

    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretData;

    @Field
    @Version
    public Long version;
}
