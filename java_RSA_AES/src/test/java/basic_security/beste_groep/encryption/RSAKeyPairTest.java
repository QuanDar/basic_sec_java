package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 04/05/2016.
 */
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

public class RSAKeyPairTest {

    private final String privateKeyPathName = "C://temp//private.key";
    private final String publicKeyPathName = "C://temp//public.key";

    @Test
    public void testToFileSystem()
            throws Exception {

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            Assert.assertNotNull(rsaKeyPair.getPrivateKey());
            Assert.assertNotNull(rsaKeyPair.getPublicKey());
            Assert.assertEquals(rsaKeyPair.getPrivateKey(), rsaKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateKeyPathName)))));
            Assert.assertEquals(rsaKeyPair.getPublicKey(), rsaKeyFactory.generatePublic(new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPathName)))));

        } catch (Exception exception) {
            Assert.fail("The testToFileSystem() test failed because: " + exception.getMessage());
        }
    }
}