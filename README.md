[![Maven Central](https://img.shields.io/maven-central/v/com.bol/spring-data-mongodb-encrypt.svg)](http://search.maven.org/#search%7Cga%7C1%7Ccom.bol)
[![Build Status](https://secure.travis-ci.org/bolcom/spring-data-mongodb-encrypt.svg)](http://travis-ci.org/bolcom/spring-data-mongodb-encrypt)


spring-data-mongodb-encrypt
---------------------------

Allows any @Field to be marked with @Encrypted for per-field encryption.

Features
--------

- integrates transparently into `spring-data-mongodb`
- supports sub-documents
- supports List, Map @Fields and nested beans
- high performance encryption
- high performance operation (no reflection at runtime)
- key versioning (to help migrating to new key without need to convert data)
- supports 256-bit AES out of the box
- supports any encryption available in Java (JCE)
- simple (500 lines of code)
- tested throughly
- 0 dependencies

For the impatient
-----------------

Add dependency:

```xml
        <dependency>
            <groupId>com.bol</groupId>
            <artifactId>spring-data-mongodb-encrypt</artifactId>
            <version>1.0.1</version>
        </dependency>
```

Configure spring:

```java
@Configuration
public class MongoDBConfiguration extends AbstractMongoConfiguration {

    // normally you would use @Value to wire a property here
    private static final byte[] secretKey = Base64.getDecoder().decode("hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=");
    private static final byte[] oldKey = Base64.getDecoder().decode("cUzurmCcL+K252XDJhhWI/A/+wxYXLgIm678bwsE2QM=");

    @Override
    protected String getDatabaseName() {
        return "test";
    }

    @Override
    @Bean
    public Mongo mongo() throws Exception {
        return new MongoClient();
    }

    @Bean
    public CryptVault cryptVault() {
        return new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, oldKey)
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(1, secretKey)
                // can be omitted if it's the highest version
                .withDefaultKeyVersion(1);
    }

    @Bean
    public EncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new EncryptionEventListener(cryptVault);
    }
}
```

Example usage:

```java
@Document
public class MyBean {
    @Id
    public String id;

    // not encrypted
    @Field
    public String nonSensitiveData;

    // encrypted primitive types
    @Field
    @Encrypted
    public String secretString;

    @Field
    @Encrypted
    public Long secretLong;

    // encrypted sub-document (MySubBean is serialized, encrypted and stored as byte[])
    @Field
    @Encrypted
    public MySubBean secretSubBean;

    // encrypted collection (list is serialized, encrypted and stored as byte[])
    @Field
    @Encrypted
    public List<String> secretStringList;

    // values containing @Encrypted fields are encrypted
    @Field
    public MySubBean nonSensitiveSubBean;

    // values containing @Encrypted fields are encrypted
    @Field
    public List<MySubBean> nonSensitiveSubBeanList;

    // encrypted map (values containing @Encrypted fields are replaced by encrypted byte[])
    @Field
    public Map<String, MySubBean> publicMapWithSecretParts;
}

public class MySubBean {
    @Field
    public String nonSensitiveData;

    @Field
    @Encrypted
    public String secretString;
}
```

The result in mongodb:

```
> db.mybean.find().pretty()
{
	"_id" : ObjectId("59ea0fb902da8d61252b9988"),
	"_class" : "com.bol.secure.MyBean",
	"nonSensitiveSubBeanList" : [
		{
			"nonSensitiveData" : "sky is blue",
			"secretString" : BinData(0,"gJNJl3Eij5hX/dJeVgJ/eATIQqahYfUxg89wtKjZL1zxL5h4PTqGqjjn4HbBXbAibw==")
		},
		{
			"nonSensitiveData" : "grass is green",
			"secretString" : BinData(0,"gL+HVZ/OtbESNtL5yWgEYVv0rhT4gdOwYFs7zKx6WGEr1dq3jj84Sq+VhQKl4EthJg==")
		}
	]
}
```

Encrypt other data
------------------

If you want to encrypt other arbitrary data, here is an example on how to do so:

```java

    @Autowired CryptVault cryptVault;

    // encrypt
    byte[] encrypted = cryptVault.encrypt("rock".getBytes());

    // decrypt
    byte[] decrypted = cryptVault.decrypt(encrypted);
    
    new String(decrypted).equals("rock");   // true 
```

If you want to use this library to encrypt arbitrary fields directly via mongo-driver:

```java
    @Autowired MongoTemplate mongoTemplate;
    @Autowired CryptVault cryptVault;

    void store(String id, String secretData) {
        byte[] bytes = secretData.getBytes();
        byte[] encrypted = cryptVault.encrypt(bytes);
        Binary binary = new Binary(encrypted);

        BasicDBObject dbObject = new BasicDBObject("_id", id);
        dbObject.put("blob", binary);

        mongoTemplate.getCollection("blobs").save(dbObject);
    }

    String load(String id) {
        DBObject result = mongoTemplate.getCollection("blobs").findOne(id);
        if (result == null) return "";

        Object blob = result.get("blob");
        if (blob == null) return "";

        byte[] encrypted = (byte[]) blob;
        byte[] decrypted = cryptVault.decrypt(encrypted);
        return new String(decrypted);
    }
```

Expected size of encrypted field
---
The mongodb driver serializes every java object into BSON. Under the hood, we use the very same BSON serialization for maximum compatibility.

You can expect the following extra sizes when you add an @Encrypted field:
- 17..33 bytes per @Encrypted attribute for encryption overhead;
- 12 bytes BSON overhead per field.

This also means that often it is better for both performance and storage size to mark a whole sub-document with @Encrypted instead of half of its fields.
You should check the resulting mongodb document's Binary field sizes to decide.


Encrypting the whole document
---
While it was not the use case for this library, it is very well possible to do whole document encryption with it.
Since the `_id` field (and all the other key fields) always have to be readable by mongodb, the best approach is to extract all the indexed keys into the root of the object, and keep the rest of the data as an @Encrypted sub-document, e.g.:

```java
@Field
@Id
public String id;

@Field
@Indexed
public long otherId;

@Field
@Encrypted
public SecretData data;
```
