package com.bol.system.cached;

import com.bol.crypt.CryptVault;
import com.bol.system.EncryptSystemTest;
import com.bol.system.MongoDBConfiguration;
import com.bol.system.MyBean;
import com.bol.system.MySubBean;
import com.mongodb.BasicDBList;
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

import java.util.*;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

/** needs mongodb running locally; FIXME: use embedmongo */
// FIXME: BSON sizes test for map and set is a bit flaky, need to investigate exact on-disk binary format deeper
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CachedMongoDBConfiguration.class})
public class CachedEncryptSystemTest extends EncryptSystemTest {
}
