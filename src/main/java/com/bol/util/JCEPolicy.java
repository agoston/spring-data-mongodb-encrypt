package com.bol.util;

import com.bol.crypt.CryptVault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This is no longer required in java8, u162. see:
 * https://bugs.openjdk.java.net/browse/JDK-8170157
 */
@Deprecated
public final class JCEPolicy {
    private static final Logger LOG = LoggerFactory.getLogger(CryptVault.class);

    private static final AtomicBoolean hackApplied = new AtomicBoolean(false);

    private JCEPolicy() {
        // ...
    }

    public static void allowUnlimitedStrength() {
        if (!hackApplied.compareAndSet(false, true)) return;

        try {
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            field.set(null, false);
        } catch (IllegalAccessException | NoSuchFieldException | ClassNotFoundException e) {
            LOG.trace("Exception caught while trying to open JCE via reflection", e);
        }
    }
}
