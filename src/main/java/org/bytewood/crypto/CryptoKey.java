package org.bytewood.crypto;

import java.security.Key;

/**
 *
 */
public interface CryptoKey {

    Key generateKey(final String password, final byte[] salt);
}
