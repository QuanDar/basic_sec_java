package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 04/05/2016.
 */
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Properties;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HybridCryptosystemTest {

    Properties properties;

    static String rawText = "John has a long mustache.";
    static String cipherText;
    static String encodedAESSecretKey;
    static String encryptedAESSecretKey;

    @Before
    public void before()
            throws Exception {

        FileReader fileReader = new FileReader(new File(System.getProperty("java.io.tmpdir") + "/acme.properties"));
        properties = new Properties();
        properties.load(fileReader);
        fileReader.close();
    }

    @Test
    public void testFirstVendorEncrypt()
            throws Exception {

        String truststoreProp = properties.getProperty("truststore");
        String truststorePasswordProp = properties.getProperty("truststorePassword");
        String truststoreAliasProp = properties.getProperty("truststoreAlias");

        FileInputStream fileInputStream = null;

        try {

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            fileInputStream = new FileInputStream(truststoreProp);
            keyStore.load(fileInputStream, truststorePasswordProp.toCharArray());

            X509Certificate x509Certificate = (X509Certificate)keyStore.getCertificate(truststoreAliasProp);
            RSAPublicKey rsaPublicKey = (RSAPublicKey)x509Certificate.getPublicKey();

            AESCipher aesCipher = new AESCipher();
            cipherText = aesCipher.encryptMessage(rawText, 1000, AESCipher.KeyLength.TWO_FIFTY_SIX);

            RSACipher rsaCipher = new RSACipher();
            encodedAESSecretKey = aesCipher.getEncodedSecretKey(aesCipher.getSecretKey());
            encryptedAESSecretKey = rsaCipher.encrypt(encodedAESSecretKey, rsaPublicKey, "RSA/ECB/PKCS1Padding", "UTF-8");

        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }

        Assert.assertNotNull(cipherText);
        Assert.assertNotNull(encodedAESSecretKey);
        Assert.assertNotNull(encryptedAESSecretKey);
    }

    @Test
    public void testSecondACMEDecrypt()
            throws Exception {

        String keystoreProp = properties.getProperty("keystore");
        String keystorePasswordProp = properties.getProperty("keystorePassword");
        String keystoreKeyPasswordProp = properties.getProperty("keystoreKeyPassword");
        String keystoreAliasProp = properties.getProperty("keystoreAlias");

        FileInputStream fileInputStream = null;
        String decryptedAESPrivateKey;
        String decryptedCipherText;

        try {

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            fileInputStream = new FileInputStream(keystoreProp);
            keyStore.load(fileInputStream, keystorePasswordProp.toCharArray());

            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey)keyStore.getKey(keystoreAliasProp, keystoreKeyPasswordProp.toCharArray());
            RSACipher rsaCipher = new RSACipher();
            decryptedAESPrivateKey = rsaCipher.decrypt(encryptedAESSecretKey, rsaPrivateCrtKey, "RSA/ECB/PKCS1Padding", "UTF-8");

            AESCipher aesCipher = new AESCipher();
            decryptedCipherText = aesCipher.decrypt(cipherText, aesCipher.getDecodedSecretKey(decryptedAESPrivateKey));

        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }

        Assert.assertEquals(encodedAESSecretKey, decryptedAESPrivateKey);
        Assert.assertEquals(decryptedCipherText, rawText);
    }
}