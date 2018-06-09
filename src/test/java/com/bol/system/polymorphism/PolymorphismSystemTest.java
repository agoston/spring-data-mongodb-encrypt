package com.bol.system.polymorphism;

import com.bol.crypt.CryptVault;
import com.bol.system.model.Person;
import com.bol.system.polymorphism.model.SubObject;
import com.bol.system.polymorphism.model.TestObject;
import com.bol.system.reflection.ReflectionMongoDBConfiguration;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.types.ObjectId;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {ReflectionMongoDBConfiguration.class})
public class PolymorphismSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(TestObject.class);
        mongoTemplate.dropCollection(Person.class);
    }

    @Test
    public void checkReflectiveEncryption() {
        TestObject testObject = new TestObject();
        SubObject subObject = new SubObject();
        subObject.field = "this is a test";
        testObject.list = Collections.singletonList(subObject);

        mongoTemplate.save(testObject);

        TestObject fromDb = mongoTemplate.findOne(query(where("_id").is(testObject.id)), TestObject.class);

        assertThat(fromDb.list, hasSize(1));
        assertThat(((SubObject) fromDb.list.get(0)).field, is(subObject.field));

        DBObject fromMongo = mongoTemplate.getCollection(TestObject.MONGO_TESTOBJECT).find(new BasicDBObject("_id", new ObjectId(testObject.id))).next();
        DBObject dbNestedList = (DBObject) fromMongo.get("list");
        DBObject dbBean = (DBObject) dbNestedList.get("0");
        Object encryptedField = dbBean.get("field");
        assertThat(encryptedField, is(instanceOf(byte[].class)));
    }
}
