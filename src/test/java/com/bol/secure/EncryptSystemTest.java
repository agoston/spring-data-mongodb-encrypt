package com.bol.secure;

import com.bol.crypt.CryptVault;
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

import java.util.Arrays;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

/** needs mongodb running locally; fixme: use embedmongo */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {MongoDBConfiguration.class})
public class EncryptSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(MyBean.class);
    }

    @Test
    public void checkEncryptPrimitives() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretString = "earth is flat     ";
        bean.secretLong = 95459L;
        bean.secretBoolean = true;
        bean.secretStringList = Arrays.asList("ear", "all", "I truly am a very very long string, oh yes, my kind sir");
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveData, is(bean.nonSensitiveData));
        assertThat(fromDb.secretString, is(bean.secretString));
        assertThat(fromDb.secretLong, is(bean.secretLong));
        assertThat(fromDb.secretBoolean, is(bean.secretBoolean));
        assertThat(fromDb.secretStringList, is(bean.secretStringList));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        assertThat(fromMongo.get(MyBean.MONGO_NONSENSITIVEDATA), is(bean.nonSensitiveData));
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRING), bean.secretString.length());
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETLONG), 8);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETBOOLEAN), 1);
        // 12 is a magic constant that seems to be the overhead when serializing list of strings to BSON with mongo driver 3.4.2
        int expectedLength = 12 + bean.secretStringList.stream().mapToInt(s -> s.length() + 8).sum();
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRINGLIST), expectedLength);
    }

    @Test
    public void checkEncryptedSubdocument() {
        MyBean bean = new MyBean();
        MySubBean subBean = new MySubBean();
        subBean.nonSensitiveData = "sky is blue";
        subBean.secretString = "   earth is round";
        bean.secretSubBean = subBean;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.secretSubBean.nonSensitiveData, is(bean.secretSubBean.nonSensitiveData));
        assertThat(fromDb.secretSubBean.secretString, is(bean.secretSubBean.secretString));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();

        int expectedLength = 12
                + MySubBean.MONGO_NONSENSITIVEDATA.length() + subBean.secretString.length() + 7
                + MySubBean.MONGO_SECRETSTRING.length() + subBean.nonSensitiveData.length() + 7;

        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSUBBEAN), expectedLength);
    }

    /** mongodb BSON serialization lengths:
     * - 10 bytes for wrapping BSONObject prefix
     * - 1 byte prefix before field name
     * - field name (1 byte/char)
     * - 1 byte 0-terminator after field name
     * - 4 byte prefix before field value
     * - field value (1byte/char)
     * - 1 byte 0-terminator after field value
     * - 2 bytes 0 terminator for wrapping BSONObject
     */
    public void assertCryptLength(Object cryptedSecret, int serializedLength) {
        assertThat(cryptedSecret, is(instanceOf(byte[].class)));
        byte[] cryptedBytes = (byte[]) cryptedSecret;

        int expectedCryptedLength = cryptVault.expectedCryptedLength(serializedLength);
        assertThat(cryptedBytes.length, is(expectedCryptedLength));
    }

    @Test
    public void consecutiveEncryptsDifferentResults() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretString = "earth is flat";
        mongoTemplate.save(bean);

        DBObject fromMongo1 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        byte[] cryptedSecret1 = (byte[]) fromMongo1.get(MyBean.MONGO_SECRETSTRING);

        mongoTemplate.save(bean);

        DBObject fromMongo2 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        byte[] cryptedSecret2 = (byte[]) fromMongo2.get(MyBean.MONGO_SECRETSTRING);

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
}
