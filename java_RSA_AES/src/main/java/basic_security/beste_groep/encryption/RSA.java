package basic_security.beste_groep.encryption;

/**
 * Created by QuanDar on 04/03/2016.
 */

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger n; // (prime number 1 - 1) * (prime number 2 - 1)
    private BigInteger d; // private exponent
    private BigInteger e;

    // p q phi mogen later een lokale scope hebben. Ze zijn nu boven gezet voor te testen.
    private BigInteger p;
    private BigInteger q;
    private BigInteger phi;



    private int bitlen = 2048; // standaard bitlengte

    /** Creeer een object - encrypteer een bericht met iemand anders zijn key. */
    public RSA(BigInteger newn, BigInteger newe) {
        n = newn;
        e = newe;
    }

    /** incrypteren + decrypteren. */
    public RSA(int bits) {
        this.bitlen = bits;
        SecureRandom r = new SecureRandom();
        p = new BigInteger(bitlen / 2, 100, r);
        q = new BigInteger(bitlen / 2, 100, r);
        /** Factorisatie, ontbinden van priemgetallen */
        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE)); // (p - 1) * (q - 1)
        e = new BigInteger("3");
        while (phi.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(phi);
    }

    /** Encrypteer een String message naar een encrypted String formaat. */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    /** Encrypt plaintext message. */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    /** Decrypt text message. */
    public synchronized String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }

    /** Decrypt BigInteger message. */
    public synchronized BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }

    /** Genereer een publiek en private key. */
    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();

        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    /** Return modulus. */
    public synchronized BigInteger getN() {
        return n;
    }

    /** Return public key. */
    public synchronized BigInteger getE() {
        return e;
    }

}