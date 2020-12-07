package com.bol.system.model;

import com.bol.secure.Encrypted;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import static com.bol.system.model.PrimitiveField.MONGO_PRIMITIVEFIELD;
import static com.bol.system.model.RenamedField.MONGO_RENAMEDFIELD;

@Document(collection = MONGO_PRIMITIVEFIELD)
public class PrimitiveField {
    public static final String MONGO_PRIMITIVEFIELD = "primitivefield";

    @Field
    public int primitiveInt;

    @Field
    @Encrypted
    public int encryptedPrimitiveInt;
}
