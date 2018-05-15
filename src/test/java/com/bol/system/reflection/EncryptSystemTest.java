package com.bol.system.reflection;

import com.bol.crypt.CryptVault;
import com.bol.secure.Encrypted;
import com.bol.system.MyBean;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;
import java.util.List;

// FIXME: add doc
// FIXME: add doc about configuring mongo mapper without _class
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {ReflectionMongoDBConfiguration.class})
public class EncryptSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(MyBean.class);
    }

    @Test
    public void checkReflectiveEncryption() {
        TestObject testObject = new TestObject();
        SubObject subObject = new SubObject();
        subObject.field = "this is a test";
        testObject.list = Collections.singletonList(subObject);

        mongoTemplate.save(testObject);
    }

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
        @Field
        List<AbstractSubObject> list;
    }

    class AbstractSubObject {
    }

    class SubObject extends AbstractSubObject {
        @Field
        @Encrypted
        String field;
    }
}
