package com.bol.system.reflection;

import com.bol.system.EncryptSystemTest;
import com.bol.system.cached.CachedMongoDBConfiguration;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/** needs mongodb running locally; FIXME: use embedmongo */
// FIXME: BSON sizes test for map and set is a bit flaky, need to investigate exact on-disk binary format deeper
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {ReflectionMongoDBConfiguration.class})
public class ReflectionEncryptSystemTest extends EncryptSystemTest {
}
