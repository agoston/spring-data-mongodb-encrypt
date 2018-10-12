package com.bol.system.cached;

import com.bol.crypt.CryptVault;
import com.bol.secure.CachedEncryptionEventListener;
import com.bol.system.MongoDBConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CachedMongoDBConfiguration extends MongoDBConfiguration {
    @Bean
    public CachedEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new CachedEncryptionEventListener(cryptVault);
    }
}
