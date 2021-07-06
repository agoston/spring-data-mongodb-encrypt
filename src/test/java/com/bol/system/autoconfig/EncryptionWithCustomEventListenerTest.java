package com.bol.system.autoconfig;

import com.bol.config.EncryptAutoConfiguration;
import com.bol.crypt.CryptVault;
import com.bol.secure.AbstractEncryptionEventListener;
import com.bol.secure.CachedEncryptionEventListener;
import com.bol.secure.ReflectionEncryptionEventListener;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("autoconfig-short")
@RunWith(SpringRunner.class)
@EnableAutoConfiguration
@SpringBootTest(classes = {EncryptionWithCustomEventListenerTest.class, EncryptionWithCustomEventListenerTest.AbstractEventListenerConfig.class, EncryptAutoConfiguration.class})
public class EncryptionWithCustomEventListenerTest {

    @Autowired(required = false) CryptVault cryptVault;
    @Autowired(required = false) AbstractEncryptionEventListener<?> eventListener;

    @Test
    public void sanityTest() {
        assertThat(cryptVault).isNotNull();
        assertThat(eventListener).isNotNull();
        assertThat(eventListener).isInstanceOf(ReflectionEncryptionEventListener.class);
    }


    @TestConfiguration
    static class AbstractEventListenerConfig {
        @Bean
        ReflectionEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
            return new ReflectionEncryptionEventListener(cryptVault);
        }
    }
}
