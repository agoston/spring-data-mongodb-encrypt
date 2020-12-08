package com.bol.system.cached;

import com.bol.system.EncryptSystemTest;
import com.bol.system.model.MyBean;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CachedMongoDBConfiguration.class})
public class CachedEncryptSystemTest extends EncryptSystemTest {

    @Test
    public void checkIfClassFieldIsAbsent() {
        MyBean bean = new MyBean();
        mongoTemplate.save(bean);

        Document fromMongo = mongoTemplate.getCollection(MyBean.MONGO_MYBEAN).find(new Document("_id", new ObjectId(bean.id))).first();

        // there should be no `_class` in there
        assertThat(fromMongo).containsOnlyKeys("_id", "version");
    }
}
