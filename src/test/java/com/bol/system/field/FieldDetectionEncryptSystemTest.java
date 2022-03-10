package com.bol.system.field;

import com.bol.crypt.CryptVault;
import com.bol.system.CryptAssert;
import com.bol.system.model.PlainBean;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.PostConstruct;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {FieldDetectionMongoDBConfiguration.class})
public class FieldDetectionEncryptSystemTest {

  @Autowired protected MongoTemplate mongoTemplate;
  @Autowired protected CryptVault cryptVault;

  private CryptAssert cryptAssert;

  @Before
  public void cleanDb() {
    mongoTemplate.dropCollection(PlainBean.class);
  }

  @PostConstruct
  void postConstruct() {
    cryptAssert = new CryptAssert(cryptVault);
  }

  @Test
  public void simpleEncryption() {
    PlainBean bean = new PlainBean();
    bean.nonSensitiveData = "grass is green";
    bean.sensitiveData = "earth is flat";
    bean.singleSubBean = new PlainBean.PlainSubBean("grass is green", "earth is flat");
    bean.subBeans = Collections.singletonList(new PlainBean.PlainSubBean("grass is green", "earth is flat"));

    mongoTemplate.save(bean);

    PlainBean fromDb = mongoTemplate.findOne(query(where("_id").is(bean.id)), PlainBean.class);

    assertThat(fromDb.nonSensitiveData).isEqualTo(bean.nonSensitiveData);
    assertThat(fromDb.sensitiveData).isEqualTo(bean.sensitiveData);
    assertThat(fromDb.singleSubBean.sensitiveData).isEqualTo(bean.singleSubBean.sensitiveData);
    assertThat(fromDb.singleSubBean.nonSensitiveData).isEqualTo(bean.singleSubBean.nonSensitiveData);
    assertThat(fromDb.subBeans.get(0).sensitiveData).isEqualTo(bean.subBeans.get(0).sensitiveData);
    assertThat(fromDb.subBeans.get(0).nonSensitiveData).isEqualTo(bean.subBeans.get(0).nonSensitiveData);

    Document fromMongo = mongoTemplate.getCollection(PlainBean.MONGO_PLAINBEAN).find(new Document("_id", new ObjectId(bean.id))).first();
    assertThat(fromMongo.get("nonSensitiveData")).isEqualTo(bean.nonSensitiveData);
    cryptAssert.assertCryptLength(fromMongo.get("sensitiveData"), bean.sensitiveData.length() + 12);

    Document subBeanDocument = (Document)fromMongo.get("singleSubBean");
    assertThat(subBeanDocument.get("nonSensitiveData")).isEqualTo(bean.singleSubBean.nonSensitiveData);
    cryptAssert.assertCryptLength(subBeanDocument.get("sensitiveData"), bean.singleSubBean.sensitiveData.length() + 12);

    Document nested = fromMongo.getList("subBeans", Document.class).get(0);
    assertThat(nested.get("nonSensitiveData")).isEqualTo(bean.subBeans.get(0).nonSensitiveData);
    cryptAssert.assertCryptLength(nested.get("sensitiveData"), bean.subBeans.get(0).sensitiveData.length() + 12);
  }

}
