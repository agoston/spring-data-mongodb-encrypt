package com.bol.secure;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.bol.util.Thrower.reThrow;

final class JCEPolicy {

    private static final AtomicBoolean allow = new AtomicBoolean(false);

    private JCEPolicy() {
        // ...
    }

    static void allowUnlimitedStrength() {
        if (!allow.compareAndSet(false, true)) {
            return;
        }

        try {
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            field.set(null, false);
        } catch (Exception e) {
            reThrow(e);
        }
    }
}
