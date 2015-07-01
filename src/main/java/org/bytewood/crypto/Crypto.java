package org.bytewood.crypto;

/**
 *
 */
public interface Crypto {
    byte[] encrypt(String in, String password, byte[] salt, byte[] iv);

    byte[] encrypt(byte[] in, String password, byte[] salt, byte[] iv);

    byte[] decrypt(byte[] in, String password, byte[] salt, byte[] iv);
}
