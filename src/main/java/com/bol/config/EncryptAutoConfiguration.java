package com.bol.config;

import com.bol.config.CryptVaultAutoConfiguration.CryptVaultConfigurationProperties;
import com.bol.crypt.CryptVault;
import com.bol.secure.AbstractEncryptionEventListener;
import com.bol.secure.CachedEncryptionEventListener;
import com.bol.secure.ReflectionEncryptionEventListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Configuration
public class EncryptAutoConfiguration {

    @Bean
    /** This allows user to create and configure their own CryptVault, or rely on a global CryptVault from the standalone `cryptvault` library;
     * This CryptVault config is merely a convenience fallback, and also offers backwards compatibility with version 2.6.2 and below */
    @ConditionalOnMissingBean(CryptVault.class)
    @ConditionalOnProperty(prefix = "mongodb.encrypt", name = "keys[0].key")
    CryptVault cryptVault(EncryptConfigurationProperties properties) {
        return new CryptVaultAutoConfiguration().cryptVault(properties);
    }

    @Bean
    @ConditionalOnMissingBean({AbstractEncryptionEventListener.class})
    @ConditionalOnBean(CryptVault.class)
    AbstractEncryptionEventListener encryptionEventListener(CryptVault cryptVault, EncryptConfigurationProperties properties) {
        AbstractEncryptionEventListener eventListener;
        if ("reflection".equalsIgnoreCase(properties.type)) {
            eventListener = new ReflectionEncryptionEventListener(cryptVault);
        } else {
            eventListener = new CachedEncryptionEventListener(cryptVault);
        }

        if (properties.silentDecryptionFailures == Boolean.TRUE) eventListener.withSilentDecryptionFailure(true);

        return eventListener;
    }

    @Component
    @ConfigurationProperties("mongodb.encrypt")
    public static class EncryptConfigurationProperties extends CryptVaultConfigurationProperties {
        String type;
        Boolean silentDecryptionFailures;

        public void setType(String type) {
            this.type = type;
        }

        public void setSilentDecryptionFailures(Boolean silentDecryptionFailures) {
            this.silentDecryptionFailures = silentDecryptionFailures;
        }
    }
}
