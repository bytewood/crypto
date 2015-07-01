package org.bytewood.crypto;

/**
 * Created by peter.wood on 03/02/2015.
 */
public class CryptoException extends RuntimeException {

    private CryptoException(Throwable cause) {
        super(cause);
    }

    public CryptoException(String message) {
        super(message);
    }

    public static RuntimeException causedBy (Exception e) {
        return (e instanceof RuntimeException) ? (RuntimeException) e : new CryptoException(e);
    }
}
