package com.bol.system.polymorphism.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

/**
 *
 * > db.testObject.find().pretty();
 * {
 * 	"_id" : ObjectId("5afaf0941a547741cd41fb5d"),
 * 	"_class" : "com.bol.system.reflection.EncryptSystemTest$TestObject",
 * 	"list" : [
 *                {
 * 			"field" : "this is a test",
 * 			"_class" : "com.bol.system.reflection.EncryptSystemTest$SubObject"
 *        }
 * 	]
 * }
 * */
@Document
public class TestObject {
    public static final String MONGO_TESTOBJECT = "testObject";

    @Id
    public String id;

    @Field
    public List<AbstractSubObject> list;
}
