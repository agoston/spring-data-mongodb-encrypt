package com.bol.secure;

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

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

/** needs mongodb running locally; fixme: use embedmongo */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {MongoDBConfiguration.class})
public class EncryptSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired EncryptionEventListener encryptionEventListener;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(MyBean.class);
    }

    @Test
    public void checkEncryptAddress() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretData = "earth is flat     ";
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveData, is(bean.nonSensitiveData));
        assertThat(fromDb.secretData, is(bean.secretData));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        Object cryptedSecret = fromMongo.get(MyBean.MONGO_SECRETDATA);
        assertThat(cryptedSecret, is(instanceOf(byte[].class)));

        byte[] cryptedBytes = (byte[]) cryptedSecret;
        CryptVersion cryptVersion = encryptionEventListener.cryptVersions[encryptionEventListener.defaultVersion];
        int expectedLength = cryptVersion.saltLength + 1 + cryptVersion.encryptedLength.apply(bean.secretData.length());
        assertThat(cryptedBytes.length, is(expectedLength));
    }

    @Test
    public void consecutiveEncryptsDifferentResults() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretData = "earth is flat";
        mongoTemplate.save(bean);

        DBObject fromMongo1 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        byte[] cryptedSecret1 = (byte[]) fromMongo1.get(MyBean.MONGO_SECRETDATA);

        mongoTemplate.save(bean);

        DBObject fromMongo2 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        byte[] cryptedSecret2 = (byte[]) fromMongo2.get(MyBean.MONGO_SECRETDATA);

        assertThat(cryptedSecret1.length, is(cryptedSecret2.length));
        // version
        assertThat(cryptedSecret1[0], is(cryptedSecret2[0]));

        // chances of having the same bytes in the same positions is negligible
        int equals = 0;
        for (int i = 1; i < cryptedSecret1.length; i++) {
            if (cryptedSecret1[i] == cryptedSecret2[i]) equals++;
        }

        assertThat("crypted fields look too much alike", equals, is(not(greaterThan(cryptedSecret1.length / 10))));
    }

    // fixme: unit test for preparing the model via reflection
    // fixme: explode code into smaller parts/classes

}
