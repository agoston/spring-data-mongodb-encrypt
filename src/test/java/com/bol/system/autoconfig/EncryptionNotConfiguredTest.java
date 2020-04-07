package com.bol.system.autoconfig;

import com.bol.crypt.CryptVault;
import com.bol.secure.CachedEncryptionEventListener;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@EnableAutoConfiguration
@SpringBootTest(classes = EncryptionNotConfiguredTest.class)
public class EncryptionNotConfiguredTest {

    @Autowired(required = false) CryptVault cryptVault;
    @Autowired(required = false) CachedEncryptionEventListener eventListener;

    @Test
    public void sanityTest() {
        assertThat(cryptVault).isNull();
        assertThat(eventListener).isNull();
    }
}
