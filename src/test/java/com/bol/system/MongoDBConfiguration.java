package com.bol.system;

import com.bol.crypt.CryptVault;
import com.bol.secure.EncryptionEventListener;
import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;

import java.util.Base64;

@Configuration
public class MongoDBConfiguration extends AbstractMongoConfiguration {

    private static final byte[] secretKey = Base64.getDecoder().decode("hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=");

    @Value("${mongodb.port:27017}") int port;

    @Override
    protected String getDatabaseName() {
        return "test";
    }

    @Override
    @Bean
    public Mongo mongo() throws Exception {
        return new MongoClient(new ServerAddress("localhost", port));
    }

    @Bean
    public CryptVault cryptVault() {
        return new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(0, secretKey)
                .withDefaultKeyVersion(0);
    }

    @Bean
    public EncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new EncryptionEventListener(cryptVault);
    }
}
