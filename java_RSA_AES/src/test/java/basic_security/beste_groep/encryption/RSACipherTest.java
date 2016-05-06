package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 06/05/2016.
 */
import org.junit.Assert;
import org.junit.Test;

public class RSACipherTest {

    private final String privateKeyPathName = "C://temp//private.key";
    private final String publicKeyPathName = "C://temp//public.key";
    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";

    @Test
    public void testEncryptDecryptWithKeyPairFiles()
            throws Exception {

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            RSACipher rsaCipher = new RSACipher();
            String encrypted = rsaCipher.encrypt("John has a long mustache.", publicKeyPathName, transformation, encoding);
            String decrypted = rsaCipher.decrypt(encrypted, privateKeyPathName, transformation, encoding);

            Assert.assertEquals(decrypted, "John has a long mustache.");

        } catch(Exception exception) {
            Assert.fail("The testEncryptWithPublicKeyFile() test failed because: " + exception.getMessage());
        }
    }

    @Test
    public void testEncryptDecryptWithKeyPair()
            throws Exception {

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);

            RSACipher rsaCipher = new RSACipher();
            String encrypted = rsaCipher.encrypt("John has a long mustache.", rsaKeyPair.getPublicKey(), transformation, encoding);
            String decrypted = rsaCipher.decrypt(encrypted, rsaKeyPair.getPrivateKey(), transformation, encoding);
            Assert.assertEquals(decrypted, "John has a long mustache.");

        } catch(Exception exception) {
            Assert.fail("The testEncryptDecryptWithKeyPair() test failed because: " + exception.getMessage());
        }
    }
}