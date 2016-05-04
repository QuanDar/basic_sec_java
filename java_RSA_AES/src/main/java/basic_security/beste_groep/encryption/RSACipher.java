package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 04/05/2016.
 */

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSACipher {

    public String encrypt(String rawText, PublicKey publicKey)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }

    public String decrypt(String cipherText, PrivateKey privateKey)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
    }
}