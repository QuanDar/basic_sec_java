package basic_security.beste_groep.encryption;

import java.io.*;

import org.junit.Assert;

/**
 * Created by QuanDar on 11/03/2016.
 */
public class AESFileTest {

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
        //Path path = Paths.get("image.jpg");

        //URL path = ClassLoader.getSystemResource("image.jpg");


        //File file = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg");
        File file = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg");

        //System.out.println(path.toString());
        //File file = new File(Package);
        //System.out.println(file.exists());

        // File fileEncrypted = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");
        File fileEncrypted = new File("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\image.jpg.encrypted");

        FileInputStream fis = new FileInputStream(file);
        FileOutputStream fos = new FileOutputStream(fileEncrypted);

        // 128, 192, 256 of de enum KeyLength gebruiken
        aes.encryptFile(AESFile.KeyLength.TWO_FIFTY_SIX, password, fis, fos);

        FileInputStream fisEncrypted = new FileInputStream(fileEncrypted);
        FileOutputStream fosDecrypted = new FileOutputStream("C:\\Users\\royXD\\Google Drive\\0- School\\L 2 PXL\\Basic security\\groepswerk basic security\\src\\main\\java\\basic_security\\beste_groep\\encryption\\decrypted_image.jpg");

         aes.decryptFile(password, fisEncrypted, fosDecrypted);
        //keylenght = aes.decryptMessage(wrongPass, fisEncrypted, fosDecrypted);
    }
}