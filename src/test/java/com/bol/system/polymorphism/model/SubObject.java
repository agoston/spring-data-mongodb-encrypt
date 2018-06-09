package com.bol.system.polymorphism.model;

import com.bol.secure.Encrypted;
import org.springframework.data.mongodb.core.mapping.Field;

public class SubObject extends AbstractSubObject {
    @Field
    @Encrypted
    public String field;
}
