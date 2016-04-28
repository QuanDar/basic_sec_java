// http://www.reindel.com/hybrid-cryptosystem-java-aes-secret-key-rsa-public-key-encryption/

/** Tutorials & extra info
 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
 */
package basic_security.beste_groep.encryption;

/**
 * Created by QuanDar on 09/03/2016.
 */

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

public class AES {

    // http://stackoverflow.com/questions/201479/what-is-base-64-encoding-used-for
    /**
     When you have some binary data that you want to ship across a network, you generally don't do it by
     just streaming the bits and bytes over the wire in a raw format.

     Why? because some media are made for streaming text. You never know -- some protocols
     may interpret your binary data as control characters (like a modem), or your binary data could be
     screwed up because the underlying protocol might think that you've entered a special
     character combination (like how FTP translates line endings).

     So to get around this, people encode the binary data into characters. Base64 is one of
     these types of encodings. Why 64? Because you can generally rely on the same 64 characters being
     present in many character sets, and you can be reasonably confident that your data's going to end
     up on the other side of the wire uncorrupted.

     */
    /**
     * http://blog.eyallupu.com/2013/11/base64-encoding-in-java-8.html
     * http://www.tutorialspoint.com/java8/java8_base64.htm
     * Encrypt een stream of data. De encrypted stream heeft een header.
     * @param base64
     *   With Java 8, Base64 has finally got its due. Java 8 now has inbuilt encoder and decoder for Base64 encoding. In Java 8, we can use three types of Base64 encoding
     *   Basic Encoding
     *      The standard encoding we all think about when we deal with Base64:
     *      no line feeds are added to the output and the output is mapped to characters
     *      in the Base64 Alphabet: A-Za-z0-9+/ (we see in a minute why is it important).
     *      Most of us are used to get annoyed when we have to encode something to be later included in a URL or as
     *   URL Encoding
     *      a filename - the problem is that the Base64 Alphabet contains meaningful characters in both URIs and filesystems
     *      (most specifically the forward slash (/)).
     *      The second type of encoder uses the alternative "URL and Filename safe" Alphabet which includes -_ (minus and underline) instead of +/.
     */
    private Base64 base64;
    private int passwordLength;
    private int saltLength;
    private int initializationVectorSeedLength;
    private SecretKey secretKey;
    private Cipher cipherAES;

    //private String cipherString = "AES/CBC/PKCS5Padding";

    /** https://docs.oracle.com/javase/8/docs/api/javax/crypto/SecretKey.html
     * public interface SecretKey
     * extends Key, Destroyable
     * Secret (symmetric key)
     *
     * Het doel van deze interface is het groeperen (en beveiligen) van alle secret key interfaces. (bijvoorbeeld AES wordt geacepteerd.
     * De equals en hashCode methode inherited van Object moeten overschreven worden, zodat de
     * secret keys worden vergelijken met het onderliggen key materiaal en niet gebasseerd op reference.
     * destroy en isDestroyed methodes van Interface Destroyable moeten override worden, om de key veilig kapot te maken.
     */
    private static SecretKey key = generateAESkey();

    /**
     * public class KeyGenerator
     * extends Object
     *
     * Een secret symmetric key generator. KeyGenerator objects zijn reusable (kan gebruikt worden om meerdere keys te maken, herbruikbaar)
     * Every implementation of the Java platform is required to support the following standard KeyGenerator algorithms with the keysizes in parentheses:
     * AES (128)
     * DES (56)
     * DESede (168)
     * HmacSHA1
     * HmacSHA256
     */
    private static SecretKey generateAESkey()  {
        try {
            // getInstance(String algorithm)
            // Returns a KeyGenerator object that generates secret keys for the specified algorithm.
            return KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String getEncodedSecretKey(SecretKey secretKey) {
        return base64.encodeToString(secretKey.getEncoded());
    }

    public SecretKey getDecodedSecretKey(String secretKey) {
        return new SecretKeySpec(base64.decode(secretKey), "AES");
    }

    public AES()
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(new Base64(), 16, 16, 16);
    }

    public AES(Base64 base64, int passwordLength, int saltLength, int initializationVectorSeedLength)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        /**
         *
         */
        try {
            this.base64 = base64;
            this.passwordLength = passwordLength;
            this.saltLength = saltLength;
            this.initializationVectorSeedLength = initializationVectorSeedLength;
            /** @param cipherAES
             * Class die de functionaliteit bied voor het encrypteren en decrypteren.
             * Een Cipher object kan je met de methode getInstance aanmaken.
             *
             * Een van de volgende transformaties (beschrijving van de operatie(of set operaties)) w
             * moet meegegeven worden aan getInstance().
             * AES/CBC/NoPadding (128)
             * AES/CBC/PKCS5Padding (128)
             * AES/ECB/NoPadding (128)
             * AES/ECB/PKCS5Padding (128)
             * DES/CBC/NoPadding (56)
             * DES/CBC/PKCS5Padding (56)
             * DES/ECB/NoPadding (56)
             * DES/ECB/PKCS5Padding (56)
             * DESede/CBC/NoPadding (168)
             * DESede/CBC/PKCS5Padding (168)
             * DESede/ECB/NoPadding (168)
             * DESede/ECB/PKCS5Padding (168)
             * RSA/ECB/PKCS1Padding (1024, 2048)
             * RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
             * RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
             */
            cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw noSuchAlgorithmException;
        } catch (NoSuchPaddingException noSuchPaddingException) {
            throw noSuchPaddingException;
        }
    }

    public byte[] encryptMessage(String rawText, int hashIterations, KeyLength keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        /**
         * @param secretKeyFactory
         * Key factories are used to convert keys (opaque cryptographic keys of type Key)
         * into key specifications (transparent representations of the underlying key material),
         * and vice versa. Secret key factories operate only on secret (symmetric) keys.
         */
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        /**
         * @param secureRandom
         * cryptographically strong random number generator (RNG).
         */
        SecureRandom secureRandom = new SecureRandom();

        /**
         * @param seed
         * GenerateSeed genereerd een random number in de vorm van een seed van Bytes.
         * Kan gebruikt worden voor andere random generators.
         */
        byte[] seed = secureRandom.generateSeed(initializationVectorSeedLength);

        /**
         * @param algorithmParameterSpec
         * The marker interface for algorithm parameter specifications.
         * The purpose is to group parameter specifications for algorithms.
         *
         * IvParameterSpec
         * This class specifies an initialization vector (IV).
         * Examples which use IVs are ciphers in feedback
         * mode, e.g., DES in CBC mode and RSA ciphers with OAEP encoding operation.
         */
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(seed);

        /**
         * @param keySpec
         * Key objects and key specifications (KeySpecs) are two different representations of key data.
         * Ciphers use Key objects to initialize their encryption algorithms,
         * but keys may need to be converted into a more portable format for transmission or storage.
         *
         * @method PBEKeySpec
         * PBE = Paswsword-based encryption
         * Een key wordt gemaakt gebaseerd op een user gekozen password.
         * Supports een transparante representatie van het onderliggende password.
         *
         * De characters worden converteerd naar PBE door een instance aan te maken van secret-key factory.
         *
         * PBEKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength)
         */
        KeySpec keySpec = new PBEKeySpec(getRandomPassword(), secureRandom.generateSeed(saltLength), hashIterations, keyLength.getBits());

        /**
         * @method SecretKeySpec
         * Out of the box solution voor het genereren van keys uit byte streams. Dit is makkelijker om het via SecretKeyFactory te doen.
         *
         * @param secretKeyFactory
         * Een factory voor secret keys.
         * Regelt de verversions tussen opaque cryptographic keys en key specfications(transparante repesentatie van de onderliggende key meta data (materiaal)).
         * https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyFactory
         * In tegenstelling tot KeyFactory die op assymetric keys werkt, werkt SecretKeyFactory alleen op symmetrische keys.
         */
        secretKey = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");

        /**
         * https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
         * init = initialize
         *
         */
        cipherAES.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);

        /**
         * https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
         * doFinal rond de gehele procedure af, nu heb je een encrypted message.
         * Omdat tekst niet zo veel ruimte in neemt kan de tekst meteen aan de methode doorgegeven worden.
         * Tekst is een single-part operation, terwijl groteren files multiple-part operations zijn.
         * Kijk je naar de onderstaande methodes om files te encrypteren, dan zie je dat het net iets anders gaat.
         */
        byte[] encryptedMessageBytes = cipherAES.doFinal(rawText.getBytes());

        /**
         * seed.length wordt gebruikt om de byte op te vullen indien deze niet groot genoeg is.
         * Wanneer een file te klein is, zal deze niet opgevuld worden met vreemde tekens.
         */
        byte[] bytesToEncode = new byte[seed.length + encryptedMessageBytes.length];
        /** https://docs.oracle.com/javase/7/docs/api/java/lang/System.html#arraycopy(java.lang.Object,%20int,%20java.lang.Object,%20int,%20int)
         * The java.lang.System.arraycopy() method copies an array from the specified source array, beginning
         * at the specified position, to the specified position of the destination array. A subsequence of array
         * components are copied from the source array referenced by src to the destination array referenced by dest.
         * The number of components copied is equal to the length argument.
         * The components at positions srcPos through srcPos + length - 1 in the source array are copied into
         * positions destPos through destPos + length - 1, respectively, of the destination array.
         * public static void arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
         */
        System.arraycopy(seed, 0, bytesToEncode, 0, seed.length);
        System.arraycopy(encryptedMessageBytes, 0, bytesToEncode, seed.length, encryptedMessageBytes.length);

        /** http://www.codejava.net/java-ee/web-services/java-web-services-binary-data-transfer-example-base64-encoding
         * Het doel van base64 is het converteren van een byte array naar een human readable standaard formaat.
         * Speciaal voor vincent.
         * Werkt met http
         */
        return base64.encode(bytesToEncode);
    }

    public String decryptMessage(byte[] encryptedText, SecretKey secretKey)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] bytesToDecode = base64.decode(encryptedText);

        byte[] emptySeed = new byte[initializationVectorSeedLength];
        System.arraycopy(bytesToDecode, 0, emptySeed, 0, initializationVectorSeedLength);

        cipherAES.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(emptySeed));

        int messageDecryptedBytesLength = bytesToDecode.length - initializationVectorSeedLength;
        byte[] messageDecryptedBytes = new byte[messageDecryptedBytesLength];
        System.arraycopy(bytesToDecode, initializationVectorSeedLength, messageDecryptedBytes, 0, messageDecryptedBytesLength);

        return new String(cipherAES.doFinal(messageDecryptedBytes));
    }


    public enum KeyLength {

        ONE_TWENTY_EIGHT(128),
        ONE_NINETY_TWO(192),
        TWO_FIFTY_SIX(256);

        private int bits;

        KeyLength(int bits) {
            this.bits = bits;
        }

        public int getBits() {
            return bits;
        }
    }

    protected char[] getRandomPassword() {

        char[] randomPassword = new char[passwordLength];

        Random random = new Random();
        for(int i = 0; i < passwordLength; i++) {
            randomPassword[i] = (char)(random.nextInt('~' - '!' + 1) + '!');
        }

        return randomPassword;
    }

    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

    // Key derivation specification - changing will break existing streams!
    private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA1";
    private static final int SALT_LENGTH = 16; // in bytes
    private static final int AUTH_KEY_LENGTH = 8; // in bytes
    private static final int ITERATIONS = 32768;

    // Process input/output streams in chunks - arbitrary
    private static final int BUFFER_SIZE = 1024;

    /**
     *
     */

    /**
     * Een extra beveiliging Salt. SecureRandom geneereert daadwerkelijk een
     */
    private static byte[] generateSalt(int length) {
        Random r = new SecureRandom();
        byte[] salt = new byte[length];
        r.nextBytes(salt);
        return salt;
    }

    private Keys keygen(int keyLength, char[] password, byte[] salt) {
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
        } catch (NoSuchAlgorithmException impossible) { return null; }
        // derive a longer key, then split into AES key and authentication key
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength + AUTH_KEY_LENGTH * 8);
        SecretKey tmp = null;
        try {
            tmp = factory.generateSecret(spec);
        } catch (InvalidKeySpecException impossible) { }
        byte[] fullKey = tmp.getEncoded();
        SecretKey authKey = new SecretKeySpec( // key for password authentication
                Arrays.copyOfRange(fullKey, 0, AUTH_KEY_LENGTH), "AES");
        SecretKey encKey = new SecretKeySpec( // key for AES encryption
                Arrays.copyOfRange(fullKey, AUTH_KEY_LENGTH, fullKey.length), "AES");
        return new Keys(encKey, authKey);
    }

    /**
     * extra klasse om de static methode te onlopen, encryption, authentication zijn niet static.
     */
    private class Keys {
        public final SecretKey encryption, authentication;
        public Keys(SecretKey encryption, SecretKey authentication) {
            this.encryption = encryption;
            this.authentication = authentication;
        }
    }

    /**
     * Encrypt een stream of data. De encrypted stream heeft een header.
     * @param keyLength
     *   key lengte voor AES encryption (128, 192, 256)
     * @param password
     *   password
     * @param input
     *   byte stream encrypted
     * @param output
     *   encrypted data stream naar een nieuwe file
     * @throws AES.StrongEncryptionNotAvailableException
     *   strength files niet geinstalleerd.
     * @throws IOException
     */

    public void encryptFile(KeyLength keyLength, char[] password, InputStream input, OutputStream output)
            throws StrongEncryptionNotAvailableException, IOException {

        // generate salt and derive keys for authentication and encryption
        byte[] salt = generateSalt(SALT_LENGTH);
        Keys keys = keygen(keyLength.getBits(), password, salt);

        // initialize AES encryption
        Cipher encrypt = null;
        try {
            encrypt = Cipher.getInstance(CIPHER_SPEC);
            encrypt.init(Cipher.ENCRYPT_MODE, keys.encryption);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException impossible) { }
        catch (InvalidKeyException e) { // 192 or 256-bit AES not available
            throw new StrongEncryptionNotAvailableException(keyLength.getBits());
        }

        // get initialization vector
        byte[] iv = null;
        try {
            iv = encrypt.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        } catch (InvalidParameterSpecException impossible) { }

        // write authentication and AES initialization data
        output.write(keyLength.getBits() / 8);
        output.write(salt);
        output.write(keys.authentication.getEncoded());
        output.write(iv);

        // read data from input into buffer, encryptMessage and write to output
        byte[] buffer = new byte[BUFFER_SIZE];
        int numRead;
        byte[] encrypted = null;
        while ((numRead = input.read(buffer)) > 0) {
            encrypted = encrypt.update(buffer, 0, numRead);
            if (encrypted != null) {
                output.write(encrypted);
            }
        }
        try { // finish encryption - do final block
            encrypted = encrypt.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException impossible) { }
        if (encrypted != null) {
            output.write(encrypted);
        }
    }

    public void decryptFile(char[] password, InputStream input, OutputStream output)
            throws InvalidPasswordException, InvalidAESStreamException, IOException,
            StrongEncryptionNotAvailableException {
        int keyLength = input.read() * 8;
        // Check validity of key length
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
            throw new InvalidAESStreamException();
        }

        // read salt, generate keys, and authenticate password
        byte[] salt = new byte[SALT_LENGTH];
        input.read(salt);
        Keys keys = keygen(keyLength, password, salt);
        byte[] authRead = new byte[AUTH_KEY_LENGTH];
        input.read(authRead);
        if (!Arrays.equals(keys.authentication.getEncoded(), authRead)) {
            throw new InvalidPasswordException();
        }

        // initialize AES decryption
        byte[] iv = new byte[16]; // 16-byte I.V. regardless of key size
        input.read(iv);
        Cipher decrypt = null;
        try {
            decrypt = Cipher.getInstance(CIPHER_SPEC);
            decrypt.init(Cipher.DECRYPT_MODE, keys.encryption, new IvParameterSpec(iv));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException impossible) { }
        catch (InvalidKeyException e) { // 192 or 256-bit AES not available
            throw new StrongEncryptionNotAvailableException(keyLength);
        }

        // read data from input into buffer, decryptMessage and write to output
        byte[] buffer = new byte[BUFFER_SIZE];
        int numRead;
        byte[] decrypted;
        while ((numRead = input.read(buffer)) > 0) {
            decrypted = decrypt.update(buffer, 0, numRead);
            if (decrypted != null) {
                output.write(decrypted);
            }
        }
        try { // finish decryption - do final block
            decrypted = decrypt.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidAESStreamException(e);
        }
        if (decrypted != null) {
            output.write(decrypted);
        }
    }


    public class InvalidPasswordException extends Exception { }

    public class StrongEncryptionNotAvailableException extends Exception {
        public StrongEncryptionNotAvailableException(int keySize) {
            super(keySize + "-bit AES encryption is niet beschikbaar op dit platform (strength files waarschijnlijk niet vervangen).");
        }
    }

    public class InvalidAESStreamException extends Exception {
        public InvalidAESStreamException() { super(); };
        public InvalidAESStreamException(Exception e) { super(e); }
    }
}
