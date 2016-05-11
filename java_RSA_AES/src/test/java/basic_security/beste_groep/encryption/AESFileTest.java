package basic_security.beste_groep.encryption;

import jdk.internal.util.xml.impl.Input;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.*;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by royXD on 11/05/2016.
 */
public class AESFileTest {
    // RSA gedeelte
    private final String privateKeyPathName = "C://temp//private.key";
    private final String publicKeyPathName = "C://temp//public.key";
    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";

    //AES gedeelte
    private AESFile aes;
    private String passwordString = "pxl";
    private static char[] password;
    private static char[] wrongPass;
    private static byte[] encryptedMessageBytes;

    @Before
    public void settings(){
        aes = new AESFile();
        password = "pxl".toCharArray();
        wrongPass = "pxxl".toCharArray();
    }

    /**
     *
     * @param privateKeyPathName
     * @param publicKeyPathName
     * @ Exception
     */
    @Test
    public void testEncryptDecryptWithKeyPairFiles()
            throws Exception {

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            RSACipher rsaCipher = new RSACipher();
            String encrypted = rsaCipher.encrypt(password.toString(), publicKeyPathName, transformation, encoding);
            String decrypted = rsaCipher.decrypt(encrypted, privateKeyPathName, transformation, encoding);

            Assert.assertEquals(decrypted, password.toString());

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
            String encrypted = rsaCipher.encrypt(password.toString(), rsaKeyPair.getPublicKey(), transformation, encoding);
            String decrypted = rsaCipher.decrypt(encrypted, rsaKeyPair.getPrivateKey(), transformation, encoding);
            Assert.assertEquals(decrypted, password.toString());

        } catch(Exception exception) {
            Assert.fail("The testEncryptDecryptWithKeyPair() test failed because: " + exception.getMessage());
        }
    }

    @org.junit.Test
    public void testFileEncryption()
            throws Exception {
/** Om een key size van 256 te gebruiken heb je de Cryptography Extension (JCE) Unlimited Strength files nodig.
 * Instaleren kan door de files te replacen in:
 *C:\Program Files\Java\jre1.8.0_73\lib\security
 *C:\Program Files\Java\jdk1.8.0_73\jre\lib\security  */
        //Download: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html




        File file = new File("C:\\Users\\quandar\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg");

        // File fileEncrypted = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");
        File fileEncrypted = new File("C:\\Users\\quandar\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");

        FileInputStream fis = new FileInputStream(file);
        FileOutputStream fos = new FileOutputStream(fileEncrypted);

        aes.encryptFile(AESFile.KeyLength.TWO_FIFTY_SIX, password, fis, fos);

        FileInputStream fisEncrypted = new FileInputStream(fileEncrypted);
        FileOutputStream fosDecrypted = new FileOutputStream("C:\\Users\\quandar\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\decrypted_image.jpg");

        aes.decryptFile(password, fisEncrypted, fosDecrypted);


    }

    @org.junit.Test
    public void testFileDecryption()
            throws Exception {

    }

    @org.junit.Test
    public void testMessageEncryption()
            throws Exception {

        String myMessage = "this is a program, hello sir";
        InputStream inputMessage = new ByteArrayInputStream(myMessage.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream output = (ByteArrayOutputStream) aes.encryptMessage(AESFile.KeyLength.ONE_NINETY_TWO, password, inputMessage);

//        PipedInputStream pin = new PipedInputStream();
//        PipedOutputStream pout = new PipedOutputStream(pin);
//
//        PrintStream out = new PrintStream(pout);
//        BufferedReader in = new BufferedReader(new InputStreamReader(pin));
//
//        System.out.println("Writing to output stream...");
//        out.println("Hello World!");
//        out.flush();
//
//        System.out.println("Text written: " + in.readLine());
        encryptedMessageBytes = output.toByteArray();


    }

    @org.junit.Test
    public void testMessageDecryption()
            throws Exception {

        InputStream input = new ByteArrayInputStream(encryptedMessageBytes);
        OutputStream outputDecrypted = aes.decryptMessage(password, input);

        System.out.println(outputDecrypted.toString());
    }
}