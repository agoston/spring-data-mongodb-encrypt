package com.bol.system;

import com.bol.crypt.*;
import com.bol.secure.AbstractEncryptionEventListener;
import com.bol.system.model.*;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import org.bson.Document;
import org.bson.types.Binary;
import org.bson.types.ObjectId;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static com.bol.crypt.CryptVault.fromSignedByte;
import static com.bol.system.model.MyBean.MONGO_NONSENSITIVEDATA;
import static com.bol.system.model.MyBean.MONGO_SECRETSTRING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

// FIXME: BSON sizes test for map and set is a bit flaky, need to investigate exact on-disk binary format deeper
public abstract class EncryptSystemTest {

    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;
    @Autowired AbstractEncryptionEventListener abstractEncryptionEventListener;

    @Before
    public void cleanDb() {
        mongoTemplate.dropCollection(MyBean.class);
        mongoTemplate.dropCollection(Person.class);
        mongoTemplate.dropCollection(RenamedField.class);
        mongoTemplate.dropCollection(PrimitiveField.class);
    }

    @Test
    public void simpleEncryption() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretString = "earth is flat     ";
        bean.secretLong = 95459L;
        bean.secretBoolean = true;
        bean.secretStringList = Arrays.asList("ear", "all", "I truly am a very very long string. I truly am a very very long string. I truly am a very very long string.");
        bean.publicStringList = Arrays.asList("ear", "all");
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nonSensitiveData).isEqualTo(bean.nonSensitiveData);
        assertThat(fromDb.secretString).isEqualTo(bean.secretString);
        assertThat(fromDb.secretLong).isEqualTo(bean.secretLong);
        assertThat(fromDb.secretBoolean).isEqualTo(bean.secretBoolean);
        assertThat(fromDb.secretStringList).isEqualTo(bean.secretStringList);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new Document("_id", new ObjectId(bean.id))).first();
        assertThat(fromMongo.get(MyBean.MONGO_NONSENSITIVEDATA)).isEqualTo(bean.nonSensitiveData);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRING), bean.secretString.length() + 12);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETLONG), 8);
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETBOOLEAN), 1);
        // 12 is a magic constant that seems to be the overhead when serializing list of strings to BSON with mongo driver 3.4.2
        int expectedLength = 12 + bean.secretStringList.stream().mapToInt(s -> s.length() + 8).sum();
        assertCryptLength(fromMongo.get(MyBean.MONGO_SECRETSTRINGLIST), expectedLength);
    }

    @Test
    public void checkEncryptPrimitives() {
        PrimitiveField bean = new PrimitiveField();
        bean.id = UUID.randomUUID();
        bean.primitiveInt = 1;
        bean.encryptedPrimitiveInt = 2;
        bean.data = new byte[]{1, 2, 3};
        mongoTemplate.save(bean);

        PrimitiveField fromDb = mongoTemplate.findOne(new Query(), PrimitiveField.class);

        assertThat(fromDb.id).isEqualTo(bean.id);
        assertThat(fromDb.primitiveInt).isEqualTo(bean.primitiveInt);
        assertThat(fromDb.encryptedPrimitiveInt).isEqualTo(bean.encryptedPrimitiveInt);
        assertThat(fromDb.data).isEqualTo(bean.data);

        // FIXME: test for DB encoding of java primitives
    }

    @Test
    public void testCustomFieldnameWorks() {
        RenamedField bean = new RenamedField();
        bean.notSecret = "not secret";
        bean.someSecret = "whacky pass";

        mongoTemplate.save(bean);

        RenamedField fromDb = mongoTemplate.findOne(new Query(), RenamedField.class);

        assertThat(fromDb.notSecret).isEqualTo(bean.notSecret);
        assertThat(fromDb.someSecret).isEqualTo(bean.someSecret);

        Document fromMongo = mongoTemplate.getCollection(RenamedField.MONGO_RENAMEDFIELD).find().first();
        assertThat(fromMongo.get(RenamedField.MONGO_NOTSECRET)).isEqualTo(bean.notSecret);
        assertThat(fromMongo.get(RenamedField.MONGO_SOMESECRET)).isNull();
        assertThat(fromMongo.get(RenamedField.MONGO_PASSWORD)).isInstanceOf(Binary.class);
    }

    @Test
    public void checkEncryptedSubdocument() {
        MyBean bean = new MyBean();
        MySubBean subBean = new MySubBean("sky is blue", "   earth is round");
        bean.secretSubBean = subBean;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.secretSubBean.nonSensitiveData).isEqualTo(bean.secretSubBean.nonSensitiveData);
        assertThat(fromDb.secretSubBean.secretString).isEqualTo(bean.secretSubBean.secretString);

        Document doc = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        DBObject fromMongo = new BasicDBObject(doc);

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

        assertThat(fromDb.nonSensitiveSubBean.nonSensitiveData).isEqualTo(bean.nonSensitiveSubBean.nonSensitiveData);
        assertThat(fromDb.nonSensitiveSubBean.secretString).isEqualTo(bean.nonSensitiveSubBean.secretString);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        Document subMongo = (Document) fromMongo.get(MyBean.MONGO_NONSENSITIVESUBBEAN);

        assertThat(subMongo.get(MySubBean.MONGO_NONSENSITIVEDATA)).isEqualTo(subBean.nonSensitiveData);
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
            assertThat(subBean.secretString).isEqualTo(subDb.secretString);
            assertThat(subBean.nonSensitiveData).isEqualTo(subDb.nonSensitiveData);
        }

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        ArrayList subMongo = (ArrayList) fromMongo.get(MyBean.MONGO_NONSENSITIVESUBBEANLIST);

        for (int i = 0; i < bean.nonSensitiveSubBeanList.size(); i++) {
            Document basicDBObject = (Document) subMongo.get(i);
            MySubBean subBean = bean.nonSensitiveSubBeanList.get(i);
            assertThat(basicDBObject.get(MySubBean.MONGO_NONSENSITIVEDATA)).isEqualTo(subBean.nonSensitiveData);
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

        assertThat(fromDb.nonSensitiveMap.get("one").secretString).isEqualTo(bean.nonSensitiveMap.get("one").secretString);
        assertThat(fromDb.nonSensitiveMap.get("one").nonSensitiveData).isEqualTo(bean.nonSensitiveMap.get("one").nonSensitiveData);
        assertThat(fromDb.nonSensitiveMap.get("two").secretString).isEqualTo(bean.nonSensitiveMap.get("two").secretString);
        assertThat(fromDb.nonSensitiveMap.get("two").nonSensitiveData).isEqualTo(bean.nonSensitiveMap.get("two").nonSensitiveData);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();

        Document mapMongo = (Document) fromMongo.get(MyBean.MONGO_NONSENSITIVEMAP);
        Document oneMongo = (Document) mapMongo.get("one");
        Document twoMongo = (Document) mapMongo.get("two");


        assertThat(oneMongo.get(MySubBean.MONGO_NONSENSITIVEDATA)).isEqualTo(map.get("one").nonSensitiveData);
        assertThat(twoMongo.get(MySubBean.MONGO_NONSENSITIVEDATA)).isEqualTo(map.get("two").nonSensitiveData);
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

        assertThat(fromDb.secretMap.get("one").secretString).isEqualTo(bean.secretMap.get("one").secretString);
        assertThat(fromDb.secretMap.get("one").nonSensitiveData).isEqualTo(bean.secretMap.get("one").nonSensitiveData);
        assertThat(fromDb.secretMap.get("two").secretString).isEqualTo(bean.secretMap.get("two").secretString);
        assertThat(fromDb.secretMap.get("two").nonSensitiveData).isEqualTo(bean.secretMap.get("two").nonSensitiveData);

        Document doc = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        DBObject fromMongo = new BasicDBObject(doc);
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

        assertThat(fromDb.secretSetPrimitive.contains("one")).isEqualTo(true);
        assertThat(fromDb.secretSetPrimitive.contains("two")).isEqualTo(true);
        assertThat(fromDb.secretSetPrimitive.size()).isEqualTo(2);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
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

        assertThat(fromDb.secretSetSubDocument.size()).isEqualTo(2);
        assertThat(fromDb.secretSetSubDocument.stream().anyMatch(s -> Objects.equals(s.nonSensitiveData, "sky is blue"))).isTrue();
        assertThat(fromDb.secretSetSubDocument.stream().anyMatch(s -> Objects.equals(s.nonSensitiveData, "grass is green"))).isTrue();

        Document doc = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        DBObject fromMongo = new BasicDBObject(doc);

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
    public void assertCryptLength(Object cryptedSecretBinary, int serializedLength) {
        assertThat(cryptedSecretBinary).isInstanceOf(Binary.class);

        Object cryptedSecretBytes = ((Binary) cryptedSecretBinary).getData();

        assertThat(cryptedSecretBytes).isInstanceOf(byte[].class);
        byte[] cryptedBytes = (byte[]) cryptedSecretBytes;

        int expectedCryptedLength = cryptVault.expectedCryptedLength(serializedLength);
        assertThat(cryptedBytes.length).isEqualTo(expectedCryptedLength);
    }

    @Test
    public void consecutiveEncryptsDifferentResults() {
        MyBean bean = new MyBean();
        bean.nonSensitiveData = "grass is green";
        bean.secretString = "earth is flat";
        mongoTemplate.save(bean);

        Document fromMongo1 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();

        Binary cryptedSecretBinary1 = (Binary) fromMongo1.get(MyBean.MONGO_SECRETSTRING);
        byte[] cryptedSecret1 = cryptedSecretBinary1.getData();
        mongoTemplate.save(bean);

        Document fromMongo2 = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        Binary cryptedSecretBinary2 = (Binary) fromMongo2.get(MyBean.MONGO_SECRETSTRING);
        byte[] cryptedSecret2 = cryptedSecretBinary2.getData();

        assertThat(cryptedSecret1.length).isEqualTo(cryptedSecret2.length);
        // version
        assertThat(cryptedSecret1[0]).isEqualTo(cryptedSecret2[0]);

        // chances of having the same bytes in the same positions is negligible
        int equals = 0;
        for (int i = 1; i < cryptedSecret1.length; i++) {
            if (cryptedSecret1[i] == cryptedSecret2[i]) equals++;
        }

        assertThat(equals).isLessThan(cryptedSecret1.length / 10).as("crypted fields look too much alike");
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

        assertThat(fromDb.encryptedNestedListMap.get("one").get(1).secretString).isEqualTo("one4");

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();

        Object binarySecret = fromMongo.get("encryptedNestedListMap");
        assertThat(binarySecret).isInstanceOf(Binary.class);

        assertThat(((Binary) binarySecret).getData()).isInstanceOf(byte[].class);
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

        assertThat(fromDb.nestedListMap.get("one").get(1).secretString).isEqualTo("one4");

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        Document dbNestedListMap = (Document) fromMongo.get("nestedListMap");
        ArrayList dbNestedList = (ArrayList) dbNestedListMap.get("one");
        Document dbBean = (Document) dbNestedList.get(1);
        Object encryptedField = dbBean.get("secretString");
        assertThat(encryptedField).isInstanceOf(Binary.class);
        Object encryptedFieldData = ((Binary) encryptedField).getData();
        assertThat(encryptedFieldData).isInstanceOf(byte[].class);
    }

    @Test
    public void testNestedMapMap() {
        MyBean bean = new MyBean();
        Map<String, MySubBean> innerMap = new HashMap<>();
        innerMap.put("one", new MySubBean("one1", "one2"));
        innerMap.put("two", new MySubBean("two1", "two2"));

        Map<String, Map<String, MySubBean>> outerMap = new HashMap<>();
        outerMap.put("inner", innerMap);
        bean.nestedMapMap = outerMap;

        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nestedMapMap.get("inner").get("two").secretString).isEqualTo("two2");

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new BasicDBObject("_id", new ObjectId(bean.id))).first();
        Document dbNestedMapMap = (Document) fromMongo.get("nestedMapMap");
        Document dbNestedMapInner = (Document) dbNestedMapMap.get("inner");
        Document dbBean = (Document) dbNestedMapInner.get("one");
        Object encryptedField = dbBean.get("secretString");
        assertThat(encryptedField).isInstanceOf(Binary.class);
        Object encryptedFieldData = ((Binary) encryptedField).getData();
        assertThat(encryptedFieldData).isInstanceOf(byte[].class);
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

        assertThat(fromDb.nestedListList.get(0).get(1).secretString).isEqualTo("one4");
        assertThat(fromDb.nestedListList.get(0).get(1).nonSensitiveData).isEqualTo("one3");

        Document doc = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new Document("_id", new ObjectId(bean.id))).first();
        ArrayList nestedListList = (ArrayList) doc.get("nestedListList");
        ArrayList nestedList = (ArrayList) nestedListList.get(1);
        Document dbDoc = (Document) nestedList.get(0);
        Object encryptedField = dbDoc.get("secretString");
        assertThat(encryptedField).isInstanceOf(Binary.class);
    }

    @Test
    public void testNestedListListNotEncrypted() {
        MyBean bean = new MyBean();
        List<List<MySubBeanNotEncrypted>> list = new ArrayList<>();
        list.add(Arrays.asList(new MySubBeanNotEncrypted("one1", "one2"), new MySubBeanNotEncrypted("one3", "one4")));
        list.add(Arrays.asList(new MySubBeanNotEncrypted("two1", "two2"), new MySubBeanNotEncrypted("two3", "two4")));
        bean.nestedListListNotEncrypted = list;
        mongoTemplate.save(bean);

        MyBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), MyBean.class);

        assertThat(fromDb.nestedListListNotEncrypted.get(0).get(1).nonSensitiveData1).isEqualTo("one3");
    }

    @Test
    public void checkSuperclassInheritedFields() {
        Person person = new Person();
        Ssn ssn = new Ssn();
        person.ssn = ssn;
        ssn.ssn = "my ssn";
        ssn.someSecret = "my secret";
        ssn.notSecret = "not secret";
        mongoTemplate.save(person);

        Person fromDb = mongoTemplate.findOne(query(where("_id").is(person.id)), Person.class);
        assertThat(fromDb.ssn.notSecret).isEqualTo(person.ssn.notSecret);
        assertThat(fromDb.ssn.someSecret).isEqualTo(person.ssn.someSecret);
        assertThat(fromDb.ssn.ssn).isEqualTo(person.ssn.ssn);

        Document fromMongo = mongoTemplate.getCollection(Person.MONGO_PERSON).find(new Document("_id", new ObjectId(person.id))).first();
        Document dbBean = (Document) fromMongo.get("ssn");
        Object encryptedField = dbBean.get("ssn");
        assertThat(encryptedField).isInstanceOf(Binary.class);
        Object encryptedFieldData = ((Binary) encryptedField).getData();
        assertThat(encryptedFieldData).isInstanceOf(byte[].class);
        Object encryptedInheritedField = dbBean.get("someSecret");
        assertThat(encryptedInheritedField).isInstanceOf(Binary.class);
        Object encryptedInheritedFieldData = ((Binary) encryptedInheritedField).getData();
        assertThat(encryptedInheritedFieldData).isInstanceOf(byte[].class);
        Object noncryptedInheritedField = dbBean.get("notSecret");
        assertThat(noncryptedInheritedField).isInstanceOf(String.class);
    }

    @Test(expected = DocumentCryptException.class)
    @DirtiesContext
    public void checkWrongKeyRoot() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));

        try {
            mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        } catch (DocumentCryptException e) {
            assertCryptException(e, "mybean", null, "secretString");
            throw e;
        }
    }

    @Test(expected = DocumentCryptException.class)
    @DirtiesContext
    public void checkWrongKeyCustomId() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.id = "customId";
        bean.secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));

        try {
            mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        } catch (DocumentCryptException e) {
            assertCryptException(e, "mybean", null, "secretString");
            throw e;
        }
    }

    @Test(expected = DocumentCryptException.class)
    @DirtiesContext
    public void checkWrongKeyDeep() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.nonSensitiveSubBean = new MySubBean();
        bean.nonSensitiveSubBean.secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));

        try {
            mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        } catch (DocumentCryptException e) {
            assertCryptException(e, "mybean", null, "nonSensitiveSubBean.secretString");
            throw e;
        }
    }

    @Test(expected = DocumentCryptException.class)
    @DirtiesContext
    public void checkWrongKeyDeepMap() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.nonSensitiveMap = new HashMap<>();
        bean.nonSensitiveMap.put("one", new MySubBean());
        bean.nonSensitiveMap.get("one").secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));

        try {
            mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        } catch (DocumentCryptException e) {
            assertCryptException(e, "mybean", null, "nonSensitiveMap.one.secretString");
            throw e;
        }
    }

    @Test(expected = DocumentCryptException.class)
    @DirtiesContext
    public void checkWrongKeyDeepList() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.nonSensitiveSubBeanList = new ArrayList<>();
        bean.nonSensitiveSubBeanList.add(new MySubBean());
        bean.nonSensitiveSubBeanList.get(0).secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));

        try {
            mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        } catch (DocumentCryptException e) {
            assertCryptException(e, "mybean", null, "nonSensitiveSubBeanList.0.secretString");
            throw e;
        }
    }

    @Test
    @DirtiesContext
    public void checkWrongKeySilentFailure() {
        // save to db, version = 0
        MyBean bean = new MyBean();
        bean.secretString = "secret";
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        // override version 0's key
        ReflectionTestUtils.setField(cryptVault, "cryptVersions", new CryptVersion[256]);
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));
        abstractEncryptionEventListener.withSilentDecryptionFailure(true);

        List<MyBean> all = mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        assertThat(all).hasSize(1);

        assertThat(all.get(0).secretString).isNull();
        assertThat(all.get(0).nonSensitiveData).isNotNull();
    }

    @Test
    @DirtiesContext
    public void checkDefaultEncryptVersion() {
        cryptVault
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(1, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="))
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));

        // default key version should now be 2
        byte[] result = cryptedResultInDb("1234");
        assertThat(result.length).isEqualTo(cryptVault.expectedCryptedLength(4 + 12));
        assertThat(fromSignedByte(result[0])).isEqualTo(2);
    }

    @Test
    @DirtiesContext
    public void checkMultipleEncryptVersion() {
        // default key version should now be 2
        byte[] result1 = cryptedResultInDb("versioning test");

        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(1, Base64.getDecoder().decode("aic7QGYCCSHyy7gYRCyNTpPThbomw1/dtWl4bocyTnU="));
        byte[] result2 = cryptedResultInDb("versioning test");

        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));
        byte[] result3 = cryptedResultInDb("versioning test");

        assertThat(fromSignedByte(result1[0])).isEqualTo(0);
        assertThat(fromSignedByte(result2[0])).isEqualTo(1);
        assertThat(fromSignedByte(result3[0])).isEqualTo(2);

        // sanity check that all of the versions are encrypted
        List<MyBean> all = mongoTemplate.find(query(where(MONGO_SECRETSTRING).is("versioning test")), MyBean.class);
        assertThat(all).hasSize(0);

        all = mongoTemplate.find(query(where(MONGO_NONSENSITIVEDATA).is(getClass().getSimpleName())), MyBean.class);
        assertThat(all).hasSize(3);

        // check that all 3 different versions are decrypted
        for (MyBean bean : all) {
            assertThat(bean.secretString).isEqualTo("versioning test");
        }
    }

    byte[] cryptedResultInDb(String value) {
        MyBean bean = new MyBean();
        bean.secretString = value;
        bean.nonSensitiveData = getClass().getSimpleName();
        mongoTemplate.insert(bean);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new Document("_id", new ObjectId(bean.id))).first();
        Object cryptedSecret = fromMongo.get(MONGO_SECRETSTRING);
        assertThat(cryptedSecret).isInstanceOf(Binary.class);
        Object cryptedSecretData = ((Binary) cryptedSecret).getData();
        assertThat(cryptedSecretData).isInstanceOf(byte[].class);
        return (byte[]) cryptedSecretData;
    }

    static void assertCryptException(Exception e, String collectionName, ObjectId objectId, String fieldName) {
        assertThat(e).isInstanceOf(DocumentCryptException.class);
        DocumentCryptException dce = (DocumentCryptException) e;
        assertThat(dce.getCollectionName()).isEqualTo(collectionName);
        if (objectId != null) assertThat(dce.getId()).isEqualTo(objectId);
        else assertThat(dce.getId()).isNotNull();

        Throwable dceCause = dce.getCause();
        assertThat(dceCause).isInstanceOf(FieldCryptException.class);
        FieldCryptException fce = (FieldCryptException) dceCause;
        assertThat(fce.getMessage()).isEqualTo(fieldName);

        Throwable fceCause = fce.getCause();
        assertThat(fceCause).isInstanceOf(CryptOperationException.class);
    }
}
