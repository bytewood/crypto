package org.bytewood.crypto;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.interfaces.PBEKey;
import java.security.Key;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class PBKDF2Test {

    private PBKDF2 testObject;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private byte[] salt;
    private String password;

    @Before
    public void setUp() throws Exception {
        testObject = new PBKDF2();
        salt = new SecureRandom().generateSeed(16);
        password = "password";
    }

    @Test
    public void generateKey() throws Exception {
        Key actual = testObject.generateKey(password, salt);

        assertThat(actual, is(instanceOf(PBEKey.class)));
        PBEKey pbeKey = (PBEKey)actual;
        assertThat(new String(pbeKey.getPassword()), is(equalTo(password)));
        assertArrayEquals(pbeKey.getSalt(), salt);
    }

    @Test
    public void generateKey_with_null_salt() throws Exception {
        thrown.expect(CryptoException.class);
        Key actual = testObject.generateKey(password, null);
    }

    @Test
    public void generateKey_with_empty_salt() throws Exception {
        thrown.expect(CryptoException.class);
        Key actual = testObject.generateKey(password, new byte[]{});
    }

    @Test
    public void generateKey_with_null_password() throws Exception {
        thrown.expect(CryptoException.class);
        testObject.generateKey(null, salt);
    }

    @Test
    public void generateKey_with_empty_password() throws Exception {
        thrown.expect(CryptoException.class);
        testObject.generateKey("", salt);
    }

}
