package basic_security.beste_groep.encryption;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

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
    // Het password is de AES key
    private static char[] password;
    private static byte[] encryptedMessageBytes;
    private static String myMessage;


    @Before
    public void settings(){
        aes = new AESFile();
        password = "pxl".toCharArray();
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
            // Het AES key password encrypteren met AES.
            String encrypted = rsaCipher.encrypt(password.toString(), publicKeyPathName, transformation, encoding);
            // AES password key decrepteren.
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
            // Het AES key password encrypteren met AES.
            String encrypted = rsaCipher.encrypt(password.toString(), rsaKeyPair.getPublicKey(), transformation, encoding);
            // AES password key decrepteren.
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

        // Locatie path naar de file
        FileInputStream fis = new FileInputStream(file);
        // Locatie naar waar de geencrypteerde file wordt geschreven
        FileOutputStream fos = new FileOutputStream(fileEncrypted);

        aes.encryptFile(AESFile.KeyLength.TWO_FIFTY_SIX, password, fis, fos);

        FileInputStream fisEncrypted = new FileInputStream(fileEncrypted);
        // Locatie waar de gedecrypteerde file wordt geschreven
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

        // Message die geencrypteerd gaat worden met AES.
        myMessage = "Beste groep PXL";
        // Message omzetten naar een ByteArrayInputStream.
        InputStream inputMessage = new ByteArrayInputStream(myMessage.getBytes(StandardCharsets.UTF_8));
        // Geencrypteerde message in de vorm van een Output Byte Array
        // Deze stap kan eventueel overgeslagen worden en de data direct om te zetten in een array van bytes.
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

        // De message in de vorm van bytes.
        encryptedMessageBytes = output.toByteArray();

        // Decrypteren
        InputStream input = new ByteArrayInputStream(encryptedMessageBytes);
        OutputStream outputDecrypted = aes.decryptMessage(password, input);

        System.out.println(outputDecrypted.toString());
        Assert.assertEquals(outputDecrypted.toString(), myMessage);
    }

    @org.junit.Test
    public void testMessageDecryption()
            throws Exception {

    }
}