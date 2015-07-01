package org.bytewood.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static java.nio.charset.Charset.defaultCharset;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 *
 */
public class PKCS5 implements Crypto {

    public static final int BLOCK_SIZE_IN_BYTES = 16;
    public static final String SECRET_KEY_ALGORITHM = "AES";

    private CryptoKey pkdf2 = new PBKDF2();

    @Override
    public byte[] encrypt(final String in, final String password, final byte[] salt, final byte[] iv) {
        final byte[] inBytes = in.getBytes(defaultCharset());
        return (encrypt(inBytes, password, salt, iv));
    }

    @Override
    public byte[] encrypt(final byte[] in, final String password, final byte[] salt, final byte[] iv) {
        try {
            Cipher cipher = getPKCS5Cipher();

            Key key = pkdf2.generateKey(password, salt);
            SecretKey sk = new SecretKeySpec(key.getEncoded(), SECRET_KEY_ALGORITHM);
            AlgorithmParameterSpec aps = new IvParameterSpec(iv);

            cipher.init(ENCRYPT_MODE, sk, aps);
            return cipher.doFinal(in);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw CryptoException.causedBy(e);
        }
    }

    private Cipher getPKCS5Cipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    @Override
    public byte[] decrypt(final byte[] in, final String password, final byte[] salt, final byte[] iv) {
        try {
            Cipher cipher = getPKCS5Cipher();

            Key key = pkdf2.generateKey(password, salt);
            SecretKey sk = new SecretKeySpec(key.getEncoded(), SECRET_KEY_ALGORITHM);
            AlgorithmParameterSpec aps = new IvParameterSpec(iv);

            cipher.init(DECRYPT_MODE, sk, aps);
            return cipher.doFinal(in);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw CryptoException.causedBy(e);
        }
    }

}
