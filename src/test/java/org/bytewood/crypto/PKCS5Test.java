package org.bytewood.crypto;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.Charset.defaultCharset;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class PKCS5Test {

    private static final String SOME_STRING = "some string";
    public static final String PASSWORD = "password";
    public static final byte[] EMPTY_BYTE_ARRAY = new byte[]{};
    private PKCS5 testObject;
    private byte[] salt;
    private SecureRandom sr;
    private byte[] iv;

    @Before
    public void setUp() throws Exception {
        testObject = new PKCS5();
        sr = new SecureRandom();
        salt = newSalt();
        iv = sr.generateSeed(PKCS5.BLOCK_SIZE_IN_BYTES);
    }

    private byte[] newSalt() {
        return sr.generateSeed(PBKDF2.KEY_SIZE_IN_BYTES);
    }

    @Test
    public void encrypt_empty_string_repeatedly_produces_a_different_cipher() throws Exception {
        byte[] previous = new byte[16];
        for (int i=0; i<100; i++) {
            byte[] encrypted = testObject.encrypt(EMPTY_BYTE_ARRAY, PASSWORD, newSalt(), iv);
            assertFalse("Iteration " + i, Arrays.equals(previous, encrypted));
            previous = encrypted.clone();
        }
    }

    @Test
    public void encrypt_decrypt_an_empty_string_returns_an_empty_array() throws Exception {
        byte[] encrypted = testObject.encrypt("", PASSWORD, salt, iv);
        assertThat(encrypted.length, is(greaterThanOrEqualTo(16)));
        byte[] original = testObject.decrypt(encrypted,PASSWORD,salt, iv);
        assertThat(original.length, is(equalTo(0)));
    }

    @Test
    public void encrypt_decrypt_a_null_string_returns_an_empty_array() throws Exception {
        byte[] encrypted = testObject.encrypt(EMPTY_BYTE_ARRAY, PASSWORD, salt, iv);
        assertThat(encrypted.length, is(greaterThanOrEqualTo(16)));
        byte[] original = testObject.decrypt(encrypted,PASSWORD,salt, iv);
        assertThat(original.length, is(equalTo(0)));
    }

    @Test
    public void encrypt_decrypt_string() throws Exception {
        final byte[] encrypted = testObject.encrypt(SOME_STRING, PASSWORD, salt, iv);
        assertThat(stringFrom(encrypted), is(not(equalTo(SOME_STRING))));

        final byte[] decrypted = testObject.decrypt(encrypted, PASSWORD, salt, iv);
        assertThat(stringFrom(decrypted), is(equalTo(SOME_STRING)));
    }

    private String stringFrom(byte[] encrypted) {
        return new String(encrypted, defaultCharset());
    }

}
