package com.bol.crypt;

import org.springframework.scheduling.annotation.Scheduled;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.function.Function;

import static com.bol.util.Thrower.reThrow;

public class CryptVault {
    static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    static final String DEFAULT_ALGORITHM = "AES";
    static final int DEFAULT_SALT_LENGTH = 16;

    private CryptVersion[] cryptVersions = new CryptVersion[256];
    int defaultVersion = -1;

    /**
     * Helper method for the most used case.
     * If you even need to change this, or need backwards compatibility, use the more advanced constructor instead.
     */
    public CryptVault with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(int version, byte[] secret) {
        if (secret.length != 32) throw new IllegalArgumentException("invalid AES key size; should be 256 bits!");

        Key key = new SecretKeySpec(secret, DEFAULT_ALGORITHM);
        CryptVersion cryptVersion = new CryptVersion(DEFAULT_SALT_LENGTH, DEFAULT_CIPHER, key, AESLengthCalculator);
        return withKey(version, cryptVersion);
    }

    public CryptVault withKey(int version, CryptVersion cryptVersion) {
        if (version < 0 || version > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[version] != null) throw new IllegalArgumentException("version " + version + " is already defined");

        cryptVersions[version] = cryptVersion;
        if (version > defaultVersion) defaultVersion = version;
        return this;
    }

    /** specifies the version used in encrypting new data. default is highest version number. */
    public CryptVault withDefaultKeyVersion(int defaultVersion) {
        if (defaultVersion < 0 || defaultVersion > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[defaultVersion] == null) throw new IllegalArgumentException("version " + defaultVersion + " is undefined");

        this.defaultVersion = defaultVersion;
        return this;
    }

    // FIXME: have a pool of ciphers (with locks & so), cipher init seems to be very costly (jmh it!)
    Cipher cipher(String cipher) {
        try {
            return Cipher.getInstance(cipher);
        } catch (Exception e) {
            throw new IllegalStateException("spring-data-mongodb-encrypt: init failed for cipher " + cipher, e);
        }
    }

    private SecureRandom SECURE_RANDOM = new SecureRandom();

    @Scheduled(initialDelay = 3_600_000, fixedDelay = 3_600_000)
    public void reinitSecureRandomHourly() {
        SECURE_RANDOM = new SecureRandom();
    }

    byte[] urandomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public byte[] encrypt(byte[] data) {
        return encrypt(defaultVersion, data);
    }

    public byte[] encrypt(int version, byte[] data) {
        CryptVersion cryptVersion = cryptVersion(version);
        try {
            int cryptedLength = cryptVersion.encryptedLength.apply(data.length);
            byte[] result = new byte[cryptedLength + cryptVersion.saltLength + 1];
            result[0] = toSignedByte(version);

            byte[] random = urandomBytes(cryptVersion.saltLength);
            IvParameterSpec iv_spec = new IvParameterSpec(random);
            System.arraycopy(random, 0, result, 1, cryptVersion.saltLength);

            Cipher cipher = cipher(cryptVersion.cipher);
            cipher.init(Cipher.ENCRYPT_MODE, cryptVersion.key, iv_spec);
            int len = cipher.doFinal(data, 0, data.length, result, cryptVersion.saltLength + 1);

            // fixme: remove this once system tests pass
            if (len < cryptedLength) System.err.println("len was " + len + " instead of " + cryptedLength);

            return result;
        } catch (Exception e) {
            return reThrow(e);
        }
    }

    public byte[] decrypt(byte[] data) {
        int version = fromSignedByte(data[0]);
        CryptVersion cryptVersion = cryptVersion(version);

        try {
            byte[] random = new byte[cryptVersion.saltLength];
            System.arraycopy(data, 1, random, 0, cryptVersion.saltLength);
            IvParameterSpec iv_spec = new IvParameterSpec(random);

            Cipher cipher = cipher(cryptVersions[version].cipher);
            cipher.init(Cipher.DECRYPT_MODE, cryptVersions[version].key, iv_spec);
            return cipher.doFinal(data, cryptVersion.saltLength + 1, data.length - cryptVersion.saltLength - 1);
        } catch (Exception e) {
            return reThrow(e);
        }
    }

    public int expectedCryptedLength(int serializedLength) {
        return expectedCryptedLength(defaultVersion, serializedLength);
    }

    public int expectedCryptedLength(int version, int serializedLength) {
        CryptVersion cryptVersion = cryptVersion(version);
        return cryptVersion.saltLength + 1 + cryptVersion.encryptedLength.apply(serializedLength);
    }

    private CryptVersion cryptVersion(int version) {
        try {
            CryptVersion result = cryptVersions[version];
            if (result == null) throw new IllegalArgumentException("version " + version + " undefined");
            return result;
        } catch (IndexOutOfBoundsException e) {
            if (version < 0) throw new IllegalStateException("encryption keys are not initialized");
            throw new IllegalArgumentException("version must be a byte (0-255)");
        }
    }

    /** AES simply pads to 128 bits */
    static final Function<Integer, Integer> AESLengthCalculator = i -> (i | 0xf) + 1;

    /** because, you know... java */
    static byte toSignedByte(int val) {
        return (byte) (val + Byte.MIN_VALUE);
    }

    /** because, you know... java */
    static int fromSignedByte(byte val) {
        return ((int) val - Byte.MIN_VALUE);
    }
}
