package com.bol.system.reflection;

import com.bol.system.EncryptSystemTest;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {ReflectionMongoDBConfiguration.class})
public class ReflectionEncryptSystemTest extends EncryptSystemTest {
}
