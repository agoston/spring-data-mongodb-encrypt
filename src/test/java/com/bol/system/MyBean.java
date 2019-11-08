package com.bol.system;

import com.bol.secure.Encrypted;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Document(collection = MyBean.MONGO_MYBEAN)
public class MyBean {
    public static final String MONGO_MYBEAN = "mybean";
    public static final String MONGO_NONSENSITIVEDATA = "nonSensitiveData";
    public static final String MONGO_NONSENSITIVESUBBEAN = "nonSensitiveSubBean";
    public static final String MONGO_NONSENSITIVESUBBEANLIST = "nonSensitiveSubBeanList";
    public static final String MONGO_SECRETSTRING = "secretString";
    public static final String MONGO_SECRETLONG = "secretLong";
    public static final String MONGO_SECRETBOOLEAN = "secretBoolean";
    public static final String MONGO_SECRETSUBBEAN = "secretSubBean";
    public static final String MONGO_SECRETSTRINGLIST = "secretStringList";
    public static final String MONGO_NONSENSITIVEMAP = "nonSensitiveMap";
    public static final String MONGO_SECRETMAP = "secretMap";
    public static final String MONGO_SECRETSETPRIMITIVE = "secretSetPrimitive";
    public static final String MONGO_SECRETSETSUBDOCUMENT = "secretSetSubDocument";

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
    public List<String> publicStringList;

    @Field
    @Encrypted
    public List<String> secretStringList;

    @Field
    public MySubBean nonSensitiveSubBean;

    @Field
    public List<MySubBean> nonSensitiveSubBeanList;

    @Field
    public Map<String, MySubBean> nonSensitiveMap;

    @Field
    @Encrypted
    public Map<String, MySubBean> secretMap;

    @Field
    @Encrypted
    public Set<String> secretSetPrimitive;

    @Field
    @Encrypted
    public Set<MySubBean> secretSetSubDocument;

    @Field
    @Encrypted
    public Map<String, List<MySubBean>> encryptedNestedListMap;

    @Field
    public Map<String, List<MySubBean>> nestedListMap;

    @Field
    @Encrypted
    public List<List<MySubBean>> encryptedNestedListList;

    @Field
    public List<List<MySubBean>> nestedListList;

    @Field
    public List<List<MySubBeanNotEncrypted>> nestedListListNotEncrypted;

    @Field
    @Version
    public Long version;
}
