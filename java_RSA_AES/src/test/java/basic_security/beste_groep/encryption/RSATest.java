package basic_security.beste_groep.encryption;

import basic_security.beste_groep.encryption.RSA;

import java.math.BigInteger;

/**
 * Created by QuanDar on 09/03/2016.
 */
public class RSATest {
    public static void main(String[] args) {
        RSA rsa = new RSA(2048);

        String text1 = "Awesome groespwerk RSA";
        System.out.println("Plaintext: " + text1);
        BigInteger plaintext = new BigInteger(text1.getBytes());

        System.out.println(plaintext);

        BigInteger ciphertext = rsa.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        plaintext = rsa.decrypt(ciphertext);

        String text2 = new String(plaintext.toByteArray());
        System.out.println("Plaintext: " + text2);
    }
}
