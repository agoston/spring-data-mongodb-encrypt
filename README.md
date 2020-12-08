[![Maven Central](https://img.shields.io/maven-central/v/com.bol/spring-data-mongodb-encrypt.svg)](http://search.maven.org/#search%7Cga%7C1%7Ccom.bol)
[![Build Status](https://secure.travis-ci.org/bolcom/spring-data-mongodb-encrypt.svg)](http://travis-ci.org/bolcom/spring-data-mongodb-encrypt)


# spring-data-mongodb-encrypt

Allows any field to be marked with `@Encrypted` for per-field encryption.

## Features

- integrates transparently into `spring-data-mongodb`
- supports nested Collections, Maps and beans
- high performance (no reflection, optimized encryption)
- key versioning (to help migrating to new key without need to convert data)
- supports 256-bit AES out of the box
- supports any encryption available in Java (via JCE)
- simple (<1000 lines of code)
- tested throughly
- no dependencies

## Backwards compatibility

For spring-data 1 projects, please use the [spring-data-1](https://github.com/bolcom/spring-data-mongodb-encrypt/tree/spring-data-1) branch.
For spring-data 2 projects, please use the [spring-data-2](https://github.com/bolcom/spring-data-mongodb-encrypt/tree/spring-data-2) branch.

## For the impatient

Add dependency:

```xml
        <dependency>
            <groupId>com.bol</groupId>
            <artifactId>spring-data-mongodb-encrypt</artifactId>
            <version>2.6.0</version>
        </dependency>
```

And add the following to your `application.yml`:

```yaml
mongodb.encrypt:
  keys:
    - version: 1
      key: hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=
```

And you're done!

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

Example result in mongodb:

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

## Manual configuration

An example if you need to manually configure spring (see also [how tests set up spring mongodb context](src/test/java/com/bol/system/MongoDBConfiguration.java)):

```java
@Configuration
public class MongoDBConfiguration extends AbstractMongoClientConfiguration {

    // normally you would use @Value to wire a property here
    private static final byte[] secretKey = Base64.getDecoder().decode("hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=");
    private static final byte[] oldKey = Base64.getDecoder().decode("cUzurmCcL+K252XDJhhWI/A/+wxYXLgIm678bwsE2QM=");

    @Override
    protected String getDatabaseName() {
        return "test";
    }

    @Override
    public MongoClient mongoClient() {
        return MongoClients.create();
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
    public CachedEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new CachedEncryptionEventListener(cryptVault);
    }
}
```


## Polymorphism (and why it's bad)

`spring-data-mongodb` supports polymorphism via a rather questionable mechanism: when the nested bean's type is not deductable from the java generic type, it would simply place an `_class` field in the document to specify the fully qualified class name for deserialization.
This has some very serious drawbacks:

- Your database becomes tightly coupled with your java code. E.g., you can't just use another code base to access the database, or during refactoring java code, you will have to take extra steps to keep it backwards compatible. Even just changing a java class name or moving it to another package would fail.

- Storing the fully qualified class name in each subdocument results in a database size increase, up to 10x in worst-case scenario. It also pollutes the object structure, making it harder to read your domain data when examining the database manually.

- Exposing class names and their properties also has some security implications.

All in all, the default settings of spring-data-mongodb is quite unoptimal. It is recommended that you do not rely on polymorphism in your spring-data-mongodb data model.

To circumvent the `_class` feature of `spring-data-mongodb`, install a custom mongo mapper:

```java
    @Override
    @Bean
    public MappingMongoConverter mappingMongoConverter(MongoDatabaseFactory databaseFactory, MongoCustomConversions customConversions, MongoMappingContext mappingContext) {
        MappingMongoConverter converter = super.mappingMongoConverter(databaseFactory, customConversions, mappingContext);
        // NB: without overriding defaultMongoTypeMapper, an _class field is put in every document
        // since we know exactly which java class a specific document maps to, this is surplus
        converter.setTypeMapper(new DefaultMongoTypeMapper(null));
        return converter;
    }
```

## So OK, polymorphism is bad, but I really really want it!

Replace the `CachedEncryptionEventListener` by `ReflectionEncryptionEventListener`: 

```java
    @Bean
    public ReflectionEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new ReflectionEncryptionEventListener(cryptVault);
    }
```

or via `application.yml`:

```yaml
mongodb.encrypt:
  type: reflection
```

Note that using reflection at runtime will come at a performance cost and the drawbacks outlined above.

## Ignore decryption failures

Sometimes (see #17) it is useful to bypass the otherwise rigid decryption framework and allow for a best-effort reading of mongodb documents. Using the `EncryptionEventListener.withSilentDecryptionFailure(true)` allows to bypass these failures and leave the failing fields empty. Example:

```java
    @Bean
    public CachedEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new CachedEncryptionEventListener(cryptVault)
                .withSilentDecryptionFailure(true);
    }
```

or, via `application.yml`:
```yaml
mongodb.encrypt:
  silent-decryption-failures: true
```

It is also possible to autowire EncryptionEventListener and change this setting on-the-fly.

## Keys

This library supports AES 256 bit keys out of the box. It's possible to extend this, check the source code (`CryptVault` specifically) on how to do so.

To generate a key, you can use the following command line:

```
dd if=/dev/urandom bs=1 count=32 | base64
```

## Exchange keys

It is advisable to rotate your keys every now and then. To do so, define a new key version in `application.yml`:

```yaml
mongodb.encrypt:
  keys:
    - version: 1
      key: hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=
    - version: 2
      key: ge2L+MA9jLA8UiUJ4z5fUoK+Lgj2yddlL6EzYIBqb1Q=
```  

`spring-data-mongodb-encrypt` would automatically use the highest versioned key for encryption by default, but supports decryption using any of the keys. This allows you to deploy a new key, and either let old data slowly get phased out, or run a nightly load+save batch job to force key migration. Once all old keys are phased out, you may remove the old key from the configuration.

You can use

```yaml
mongodb.encrypt:
  default-key: 1
```

to override which version of the defined keys is considered 'default'.


## Encrypt other data

It's perfectly possible to use the powerful encryption functionality of this library for custom purposes. Example:

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

## Encrypting the whole document

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

If you can't afford to reveal the keys, you could use a high-performing hash like Guava's murmur3 to hash the keys before exposing them, compound or independently.

## Encrypting an indexed field

Since this library encrypts data *before* it is sent to mongodb, there is no point in indexing an encrypted field. However, an approach that worked remarkably well in the past was to put a calculated field next to the encrypted one that contains the hashed value (e.g. Guava's murmur3) of the encrypted field.

When searching by index, create a hash of the lookup key and search with that against the hashed field. Normally, you'd have 0 (if not exists) or 1 (exists) hits. However, because hashing can result in collisions, you also have to process the case of more than 1 hits, in which case you'd have to load all the matching documents (during which the encrypted field is decrypted by this library), and compare the now-decrypted field to find your exact match.


## Expected size of encrypted field

The mongodb driver serializes every java object into BSON. Under the hood, we use the very same BSON serialization for maximum compatibility.

You can expect the following extra sizes when you add an @Encrypted field:
- 17..33 bytes for encryption overhead (salt + padding);
- 12 bytes for BSON serialization overhead.

This also means that often it is better for both performance and storage size to mark a whole sub-document with @Encrypted instead of half of its fields.
You should check the resulting mongodb document's Binary field sizes to decide.
