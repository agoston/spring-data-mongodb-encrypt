package com.bol.system.polymorphism;

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
class TestObject {
    @Id
    public String id;

    @Field
    List<AbstractSubObject> list;
}
