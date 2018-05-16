package com.bol.system.reflection;

import com.bol.secure.Encrypted;
import org.springframework.data.mongodb.core.mapping.Field;

class SubObject extends AbstractSubObject {
    @Field
    @Encrypted
    String field;
}
