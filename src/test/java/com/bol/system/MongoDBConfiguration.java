package com.bol.system;

import com.bol.crypt.CryptVault;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;

import java.util.Base64;
import java.util.Collection;
import java.util.Collections;

@Configuration
public abstract class MongoDBConfiguration extends AbstractMongoClientConfiguration {

    private static final byte[] secretKey = Base64.getDecoder().decode("hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=");

    @Value("${mongodb.port:27017}")
    int port;

    @Override
    protected String getDatabaseName() {
        return "test";
    }

    @Override
    protected Collection<String> getMappingBasePackages() {
        return Collections.singletonList(MongoDBConfiguration.class.getPackage().getName());
    }

    @Override
    public MongoClient mongoClient() {
        String connectionString = "mongodb://localhost:" + port;
        return MongoClients.create(connectionString);
    }

    @Bean
    public CryptVault cryptVault() {
        return new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, secretKey)
                .withDefaultKeyVersion(0);
    }
}
