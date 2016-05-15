package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 04/05/2016.
 */

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSACipher {

	//Voor file locatie 
    public String encrypt(String rawText, String publicKeyPath, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPath)));

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec));

        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(encoding)));
    }

    //encryptie van AES sleutel
    public String encryptSymmetricKey(String rawText, PublicKey serverKey, String transformation, String encoding) 
    		throws IOException, GeneralSecurityException {
    	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverKey.getEncoded());

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec));

        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(encoding)));
	}
    
    public String encrypt(String rawText, PublicKey publicKey, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(encoding)));
    }

    public String encryptKey(String rawText, PublicKey publicKey, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(encoding)));
    }

    public String decrypt(String cipherText, String privateKeyPath, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateKeyPath)));

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec));

        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), encoding);
    }

    public String decrypt(String cipherText, PrivateKey privateKey, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), encoding);
    }
}