package basic_security.beste_groep.encryption;

/**
 * Created by royXD on 04/05/2016.
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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

//        try {
//
//            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
//            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);
//
//            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
//
//            Assert.assertNotNull(rsaKeyPair.getPrivateKey());
//            Assert.assertNotNull(rsaKeyPair.getPublicKey());
//            Assert.assertEquals(rsaKeyPair.getPrivateKey(), rsaKeyFactory.generatePrivate(
//                    new PKCS8EncodedKeySpec(IOUtils.toByteArray(
//                            new FileInputStream(privateKeyPathName)))));
//
//            Assert.assertEquals(rsaKeyPair.getPublicKey(), rsaKeyFactory.generatePublic(new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPathName)))));
//
//        } catch (Exception exception) {
//            Assert.fail("The testToFileSystem() test failed because: " + exception.getMessage());
//        }
    }

    @org.junit.Test
    public void testFileEncryption()
            throws Exception {
/** Om een key size van 256 te gebruiken heb je de Cryptography Extension (JCE) Unlimited Strength files nodig.
 * Instaleren kan door de files te replacen in:
 *C:\Program Files\Java\jre1.8.0_73\lib\security
 *C:\Program Files\Java\jdk1.8.0_73\jre\lib\security  */
        //Download: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

        AESFile aes = new AESFile();
        char[] password = "pxl".toCharArray();
        char[] wrongPass = "pxxl".toCharArray();

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            Assert.assertNotNull(rsaKeyPair.getPrivateKey());
            Assert.assertNotNull(rsaKeyPair.getPublicKey());
            Assert.assertEquals(rsaKeyPair.getPrivateKey(), rsaKeyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(IOUtils.toByteArray(
                            new FileInputStream(privateKeyPathName)))));

            Assert.assertEquals(rsaKeyPair.getPublicKey(), rsaKeyFactory.generatePublic(new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPathName)))));

        } catch (Exception exception) {
            Assert.fail("The testToFileSystem() test failed because: " + exception.getMessage());
        }


        File file = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg");

        // File fileEncrypted = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");
        File fileEncrypted = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");

        FileInputStream fis = new FileInputStream(file);
        FileOutputStream fos = new FileOutputStream(fileEncrypted);

        aes.encryptFile(AESFile.KeyLength.TWO_FIFTY_SIX, password, fis, fos);

        FileInputStream fisEncrypted = new FileInputStream(fileEncrypted);
        FileOutputStream fosDecrypted = new FileOutputStream("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\decrypted_image.jpg");

        aes.decryptFile(password, fisEncrypted, fosDecrypted);
        //keylenght = aes.decryptMessage(wrongPass, fisEncrypted, fosDecrypted);
    }
}