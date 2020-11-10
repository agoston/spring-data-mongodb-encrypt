package com.bol.system.model;

import com.bol.secure.Encrypted;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;
import java.util.Map;
import java.util.Set;

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

    @Field
    public Set<Map<String, List<Set<Map<String, MyBean>>>>> nestedCollectionsBean;

    public MySubBean() {}

    public MySubBean(String nonSensitiveData, String secretString) {
        this.nonSensitiveData = nonSensitiveData;
        this.secretString = secretString;
    }
}
