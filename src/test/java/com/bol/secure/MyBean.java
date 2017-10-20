package com.bol.secure;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

@Document(collection = MyBean.MONGO_MYBEAN)
public class MyBean {
    public static final String MONGO_MYBEAN = "mybean";
    public static final String MONGO_NONSENSITIVEDATA = "nonSensitiveData";
    public static final String MONGO_NONSENSITIVESUBBEAN = "nonSensitiveSubBean";
    public static final String MONGO_SECRETSTRING = "secretString";
    public static final String MONGO_SECRETLONG = "secretLong";
    public static final String MONGO_SECRETBOOLEAN = "secretBoolean";
    public static final String MONGO_SECRETSUBBEAN = "secretSubBean";
    public static final String MONGO_SECRETSTRINGLIST = "secretStringList";

    @Id
    public String id;

    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretString;

    @Field
    @Encrypted
    public Long secretLong;

    @Field
    @Encrypted
    public Boolean secretBoolean;

    @Field
    @Encrypted
    public MySubBean secretSubBean;

    @Field
    @Encrypted
    public List<String> secretStringList;

    @Field
    public MySubBean nonSensitiveSubBean;

    @Field
    @Version
    public Long version;
}
