package com.bol.system.reflection;

import com.bol.crypt.CryptVault;
import com.bol.system.MyBean;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

// FIXME: add doc
// FIXME: add doc about configuring mongo mapper without _class
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {ReflectionMongoDBConfiguration.class})
public class EncryptSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(TestObject.class);
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
        assertThat(((SubObject)fromDb.list.get(0)).field, is(subObject.field));
    }
}
