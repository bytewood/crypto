package org.bytewood.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 *
 */
public class PBKDF2 implements CryptoKey {

    public static final int ITERATIONS = 1024;
    public static final int KEY_SIZE_IN_BYTES = 16;

    private SecretKeyFactory secretKeyFactory;

    public PBKDF2() {
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw CryptoException.causedBy(e);
        }
    }

    @Override
    public Key generateKey(final String password, final byte[] salt) {
        validatePassword(password);
        validateSalt(salt);
        KeySpec keySpec = createPBEKey(password, salt);
        try {
            return secretKeyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw CryptoException.causedBy(e);
        }
    }

    private void validatePassword(final String password) {
        if (invalidPassword(password)) {
            throw new CryptoException("Invalid: Password cannot be null or empty.");
        }
    }

    private boolean invalidPassword(final String password) {
        return (password == null || password.length()==0);
    }

    private void validateSalt(final byte[] salt) {
        if (invalidSalt(salt)) {
            throw new CryptoException("Invalid: Salt byte length must be " + PBKDF2.KEY_SIZE_IN_BYTES + ".");
        }
    }

    private PBEKeySpec createPBEKey(final String password, final byte[] salt) {
        return new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE_IN_BYTES*8);
    }

    private boolean invalidSalt(final byte[] salt) {
        return (salt == null || salt.length != PBKDF2.KEY_SIZE_IN_BYTES);
    }

}
