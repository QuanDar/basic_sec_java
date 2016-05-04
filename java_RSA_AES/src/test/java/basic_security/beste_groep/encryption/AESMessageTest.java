package basic_security.beste_groep.encryption;

import org.junit.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by royXD on 04/05/2016.
 */
public class AESMessageTest {
    @org.junit.Test
    public void testEncryptionDecryption()
            throws Exception {

        AESMessage aesMessages = new AESMessage();
        /** Om een key size van 256 te gebruiken heb je de Cryptography Extension (JCE) Unlimited Strength files nodig.
         * Instaleren kan door de files te replacen in:
         *C:\Program Files\Java\jre1.8.0_73\lib\security
         *C:\Program Files\Java\jdk1.8.0_73\jre\lib\security  */
        //Download: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

        // (tekst, aantal itiraties, key size)
        byte[] encrypted = aesMessages.encryptMessage("John has a long mustache.", 1000, AESMessage.KeyLength.TWO_FIFTY_SIX);
        String decrypted = aesMessages.decryptMessage(encrypted, aesMessages.getSecretKey());
        Assert.assertEquals(decrypted, "John has a long mustache.");
    }

    private static void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while((i=is.read(b))!=-1) {
            os.write(b, 0, i);
        }
    }
}


