package com.bol.system.model;

import com.bol.secure.Encrypted;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.UUID;

import static com.bol.system.model.PrimitiveField.MONGO_PRIMITIVEFIELD;

/*
> db.primitivefield.find().pretty();
{
	"_id" : BinData(3,"m0jcj60kTHxdZZriPCPxuw=="),
	"data" : BinData(0,"gIUv9oVQRNFDcialLXqdd/MiSrrkuSmOLmFr1M+x5hBk"),
	"primitiveInt" : 1,
	"encryptedPrimitiveInt" : BinData(0,"gCIePEAEVzZ8ymqz30WeSVCqkq3sLtk0Pc+6rjgMDaoO"),
	"_class" : "com.bol.system.model.PrimitiveField"
}
 */
@Document(collection = MONGO_PRIMITIVEFIELD)
public class PrimitiveField {
    public static final String MONGO_PRIMITIVEFIELD = "primitivefield";

    // try using UUID as ID
    @Id
    public UUID id;

    @Field
    @Encrypted
    public byte[] data;

    @Field
    public int primitiveInt;

    @Field
    @Encrypted
    public int encryptedPrimitiveInt;
}
