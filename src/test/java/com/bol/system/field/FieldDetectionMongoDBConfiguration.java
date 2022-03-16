package com.bol.system.field;

import com.bol.crypt.CryptVault;
import com.bol.secure.ReflectionEncryptionEventListener;
import com.bol.system.MongoDBConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Configuration
public class FieldDetectionMongoDBConfiguration extends MongoDBConfiguration {

    private final Set<String> fields = new HashSet<>(Arrays.asList("PlainBean.sensitiveData", "PlainSubBean.sensitiveData"));

    @Bean
    public ReflectionEncryptionEventListener encryptionEventListener(CryptVault cryptVault) {
        return new ReflectionEncryptionEventListener(cryptVault, field -> {
            String fieldName = field.getDeclaringClass().getSimpleName() + "." + field.getName();
            return fields.contains(fieldName);
        });
    }
}
