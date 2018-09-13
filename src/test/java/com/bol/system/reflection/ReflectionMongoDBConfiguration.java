package com.bol.system.reflection;

import com.bol.crypt.CryptVault;
import com.bol.secure.ReflectionEncryptionEventListener;
import com.bol.system.MongoDBConfiguration;
import com.mongodb.MongoClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ReflectionMongoDBConfiguration extends MongoDBConfiguration {
    @Bean
    public ReflectionEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new ReflectionEncryptionEventListener(cryptVault);
    }

    @Override
    public MongoClient mongoClient() {
        return new MongoClient();
    }
}
