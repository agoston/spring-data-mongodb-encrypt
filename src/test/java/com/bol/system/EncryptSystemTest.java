package com.bol.system;

import com.bol.crypt.CryptVault;
import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.types.ObjectId;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;

import java.util.*;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

// FIXME: BSON sizes test for map and set is a bit flaky, need to investigate exact on-disk binary format deeper
public abstract class EncryptSystemTest {

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
        bean.secretStringList = Arrays.asList("ear", "all", "I truly am a very very long string. I truly am a very very long string. I truly am a very very long string.");
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveData, is(bean.nonSensitiveData));
        assertThat(fromDb.secretString, is(bean.secretString));
        assertThat(fromDb.secretLong, is(bean.secretLong));
        assertThat(fromDb.secretBoolean, is(bean.secretBoolean));
        assertThat(fromDb.secretStringList, is(bean.secretStringList));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        assertThat(fromMongo.get(MyBean.MONGO_NONSENSITIVEDATA), is(bean.nonSensitiveData));
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRING), bean.secretString.length() + 12);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETLONG), 8);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETBOOLEAN), 1);
        // 12 is a magic constant that seems to be the overhead when serializing list of strings to BSON with mongo driver 3.4.2
        int expectedLength = 12 + bean.secretStringList.stream().mapToInt(s -> s.length() + 8).sum();
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRINGLIST), expectedLength);
    }

    @Test
    public void checkEncryptedSubdocument() {
        MyBean bean = new MyBean();
        MySubBean subBean = new MySubBean("sky is blue", "   earth is round");
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

    @Test
    public void checkNonEncryptedSubdocument() {
        MyBean bean = new MyBean();
        MySubBean subBean = new MySubBean("sky is blue", "   earth is round");
        bean.nonSensitiveSubBean = subBean;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveSubBean.nonSensitiveData, is(bean.nonSensitiveSubBean.nonSensitiveData));
        assertThat(fromDb.nonSensitiveSubBean.secretString, is(bean.nonSensitiveSubBean.secretString));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        DBObject subMongo = (DBObject) fromMongo.get(MyBean.MONGO_NONSENSITIVESUBBEAN);

        assertThat(subMongo.get(MySubBean.MONGO_NONSENSITIVEDATA), is(subBean.nonSensitiveData));
        assertCryptLength(subMongo.get(MySubBean.MONGO_SECRETSTRING), subBean.secretString.length() + 12);
    }

    @Test
    public void checkNonEncryptedSubdocumentList() {
        MyBean bean = new MyBean();
        bean.nonSensitiveSubBeanList = Arrays.asList(
                new MySubBean("sky is blue", "earth is round "),
                new MySubBean(" grass is green ", " earth is cubic ")
        );
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        for (int i = 0; i < bean.nonSensitiveSubBeanList.size(); i++) {
            MySubBean subBean = bean.nonSensitiveSubBeanList.get(i);
            MySubBean subDb = fromDb.nonSensitiveSubBeanList.get(i);
            assertThat(subBean.secretString, is(subDb.secretString));
            assertThat(subBean.nonSensitiveData, is(subDb.nonSensitiveData));
        }

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        BasicDBList subMongo = (BasicDBList) fromMongo.get(MyBean.MONGO_NONSENSITIVESUBBEANLIST);

        for (int i = 0; i < bean.nonSensitiveSubBeanList.size(); i++) {
            BasicDBObject basicDBObject = (BasicDBObject) subMongo.get(i);
            MySubBean subBean = bean.nonSensitiveSubBeanList.get(i);
            assertThat(basicDBObject.get(MySubBean.MONGO_NONSENSITIVEDATA), is(subBean.nonSensitiveData));
            assertCryptLength(basicDBObject.get(MySubBean.MONGO_SECRETSTRING), subBean.secretString.length() + 12);
        }
    }

    @Test
    public void checkNonEncryptedMap() {
        MyBean bean = new MyBean();
        Map<String, MySubBean> map = new HashMap<>();
        map.put("one", new MySubBean("sky is blue", "                 earth is round"));
        map.put("two", new MySubBean("grass is green", "earth is flat"));
        bean.nonSensitiveMap = map;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveMap.get("one").secretString, is(bean.nonSensitiveMap.get("one").secretString));
        assertThat(fromDb.nonSensitiveMap.get("one").nonSensitiveData, is(bean.nonSensitiveMap.get("one").nonSensitiveData));
        assertThat(fromDb.nonSensitiveMap.get("two").secretString, is(bean.nonSensitiveMap.get("two").secretString));
        assertThat(fromDb.nonSensitiveMap.get("two").nonSensitiveData, is(bean.nonSensitiveMap.get("two").nonSensitiveData));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        DBObject mapMongo = (DBObject) fromMongo.get(MyBean.MONGO_NONSENSITIVEMAP);
        DBObject oneMongo = (DBObject) mapMongo.get("one");
        DBObject twoMongo = (DBObject) mapMongo.get("two");

        assertThat(oneMongo.get(MySubBean.MONGO_NONSENSITIVEDATA), is(map.get("one").nonSensitiveData));
        assertThat(twoMongo.get(MySubBean.MONGO_NONSENSITIVEDATA), is(map.get("two").nonSensitiveData));
        assertCryptLength(oneMongo.get(MySubBean.MONGO_SECRETSTRING), map.get("one").secretString.length() + 12);
        assertCryptLength(twoMongo.get(MySubBean.MONGO_SECRETSTRING), map.get("two").secretString.length() + 12);
    }

    @Test
    public void checkEncryptedMap() {
        MyBean bean = new MyBean();
        Map<String, MySubBean> map = new HashMap<>();
        map.put("one", new MySubBean("sky is blue", "                 earth is round"));
        map.put("two", new MySubBean("grass is green", "earth is flat"));
        bean.secretMap = map;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.secretMap.get("one").secretString, is(bean.secretMap.get("one").secretString));
        assertThat(fromDb.secretMap.get("one").nonSensitiveData, is(bean.secretMap.get("one").nonSensitiveData));
        assertThat(fromDb.secretMap.get("two").secretString, is(bean.secretMap.get("two").secretString));
        assertThat(fromDb.secretMap.get("two").nonSensitiveData, is(bean.secretMap.get("two").nonSensitiveData));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();

        int expectedLength = 12
                + "one".length() + 7
                + "two".length() + 7
                + MySubBean.MONGO_NONSENSITIVEDATA.length() + map.get("one").secretString.length() + 7
                + MySubBean.MONGO_SECRETSTRING.length() + map.get("one").nonSensitiveData.length() + 7
                + MySubBean.MONGO_NONSENSITIVEDATA.length() + map.get("two").secretString.length() + 7
                + MySubBean.MONGO_SECRETSTRING.length() + map.get("two").nonSensitiveData.length() + 7;

        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETMAP), expectedLength);
    }

    @Test
    public void checkEncryptedSetPrimitive() {
        MyBean bean = new MyBean();
        Set<String> set = new HashSet<>();
        set.add("one");
        set.add("two");
        bean.secretSetPrimitive = set;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.secretSetPrimitive.contains("one"), is(true));
        assertThat(fromDb.secretSetPrimitive.contains("two"), is(true));
        assertThat(fromDb.secretSetPrimitive.size(), is(2));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();

        int expectedLength = 12
                + "one".length() + 7
                + "two".length() + 7;

        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSETPRIMITIVE), expectedLength);
    }

    @Test
    public void checkEncryptedSetSubDocument() {
        MyBean bean = new MyBean();
        Set<MySubBean> set = new HashSet<>();
        set.add(new MySubBean("sky is blue", "                 earth is round"));
        set.add(new MySubBean("grass is green", "earth is flat"));
        bean.secretSetSubDocument = set;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.secretSetSubDocument.size(), is(2));
        assertTrue(fromDb.secretSetSubDocument.stream().anyMatch(s -> Objects.equals(s.nonSensitiveData, "sky is blue")));
        assertTrue(fromDb.secretSetSubDocument.stream().anyMatch(s -> Objects.equals(s.nonSensitiveData, "grass is green")));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();

        int expectedLength = 12
                + MySubBean.MONGO_NONSENSITIVEDATA.length() + "sky is blue".length() + 12
                + MySubBean.MONGO_SECRETSTRING.length() + "                 earth is round".length() + 12
                + MySubBean.MONGO_NONSENSITIVEDATA.length() + "grass is green".length() + 12
                + MySubBean.MONGO_SECRETSTRING.length() + "earth is flat".length() + 12;

        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSETSUBDOCUMENT), expectedLength);
    }

    /**
     * simplistic mongodb BSON serialization lengths:
     * - 10 bytes for wrapping BSONObject prefix
     * - 1 byte prefix before field name
     * - field name (1 byte/char)
     * - 1 byte 0-terminator after field name
     * - 4 byte prefix before field value
     * - field value (1byte/char)
     * - 1 byte 0-terminator after field value
     * - 2 bytes 0 terminator for wrapping BSONObject
     * <p>
     * (e.g. for a single primitive string, 12 extra bytes are added above its own length)
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

    @Test
    public void testEncryptedNestedListMap() {
        MyBean bean = new MyBean();
        Map<String, List<MySubBean>> map = new HashMap<>();
        map.put("one", Arrays.asList(new MySubBean("one1", "one2"), new MySubBean("one3", "one4")));
        map.put("two", Arrays.asList(new MySubBean("two1", "two2"), new MySubBean("two3", "two4")));
        bean.encryptedNestedListMap = map;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.encryptedNestedListMap.get("one").get(1).secretString, is("one4"));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        assertThat(fromMongo.get("encryptedNestedListMap"), is(instanceOf(byte[].class)));
    }

    @Test
    public void testNestedListMap() {
        MyBean bean = new MyBean();
        Map<String, List<MySubBean>> map = new HashMap<>();
        map.put("one", Arrays.asList(new MySubBean("one1", "one2"), new MySubBean("one3", "one4")));
        map.put("two", Arrays.asList(new MySubBean("two1", "two2"), new MySubBean("two3", "two4")));
        bean.nestedListMap = map;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nestedListMap.get("one").get(1).secretString, is("one4"));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        DBObject dbNestedListMap = (DBObject) fromMongo.get("nestedListMap");
        DBObject dbNestedList = (DBObject) dbNestedListMap.get("one");
        DBObject dbBean = (DBObject) dbNestedList.get("1");
        Object encryptedField = dbBean.get("secretString");
        assertThat(encryptedField, is(instanceOf(byte[].class)));
    }

    @Test
    public void testNestedListList() {
        MyBean bean = new MyBean();
        List<List<MySubBean>> list = new ArrayList<>();
        list.add(Arrays.asList(new MySubBean("one1", "one2"), new MySubBean("one3", "one4")));
        list.add(Arrays.asList(new MySubBean("two1", "two2"), new MySubBean("two3", "two4")));
        bean.nestedListList = list;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nestedListList.get(0).get(1).secretString, is("one4"));

        DBObject fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).next();
        DBObject dbNestedListMap = (DBObject) fromMongo.get("nestedListList");
        DBObject dbNestedList = (DBObject) dbNestedListMap.get("1");
        DBObject dbBean = (DBObject) dbNestedList.get("1");
        Object encryptedField = dbBean.get("secretString");
        assertThat(encryptedField, is(instanceOf(byte[].class)));
    }
}
