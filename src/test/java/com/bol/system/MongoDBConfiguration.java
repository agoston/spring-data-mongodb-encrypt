package com.bol.system;

import com.bol.crypt.CryptVault;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;

import java.util.Base64;
import java.util.Collection;
import java.util.Collections;

@Configuration
public abstract class MongoDBConfiguration extends AbstractMongoConfiguration {

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

    @Bean
    public CryptVault cryptVault() {
        return new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, secretKey)
                .withDefaultKeyVersion(0);
    }
}
