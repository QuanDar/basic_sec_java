package basic_security.beste_groep.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.UnsupportedAudioFileException;
import javax.swing.JTextPane;

import basic_security.beste_groep.Hash.Hash;
import basic_security.beste_groep.encryption.AESFile;
import basic_security.beste_groep.encryption.AESFile.KeyLength;
import basic_security.beste_groep.encryption.AESFile.StrongEncryptionNotAvailableException;
import basic_security.beste_groep.encryption.RSACipher;
import basic_security.beste_groep.encryption.RSAKeyPair;
import basic_security.beste_groep.sslServer.SSL_Client;
import basic_security.beste_groep.view.TCPClient;

public class Controller {
	private final String transformation = "RSA/ECB/PKCS1Padding";
	private final String encoding = "UTF-8";
	private char[] password = "pxl".toCharArray();

	private JTextPane log;
	
	private String _hashOriginalFile;
	private String _hashSymmetricEncryptedFile;
	
	private File symmetricEncryptedFile = new File("File_1");
	
	//part of the package
	private RSAKeyPair rsaKeyPair;

	private PrivateKey _RSAPrivateKey;
	private PublicKey _RSAPublicKey;
	private String _encryptedAesKey;
	private String _encryptedHash;
	
	private PublicKey _publicKeyServer;
	
	private AESFile _aes = new AESFile();
	private RSACipher _rsaCipher = new RSACipher();
	

	private boolean _encryptedFilesExist;

	public Controller(JTextPane tp) {
		this.log = tp;
	}

	public void updateLog(String text) {
		log.setText(log.getText() + text + "\n");
	}

	public void generateSymmetricKey(String type) {
		updateLog("Symmetric " + type + " key generated.");
	}

	public void generateRSAKeys() throws GeneralSecurityException, IOException {
		if (_encryptedFilesExist) {
			symmetricEncryptedFile.delete();
			updateLog("Previous encrypted files are now deleted because new keys were generated.");
		}
		//_rsaPair = new RSAKeyPair(2048);
		//generatePrivateRSAKey(_rsaPair);
		//generatePublicRSAKey(_rsaPair);

		rsaKeyPair = new RSAKeyPair(2048);

		RSACipher rsaCipher = new RSACipher();

		//AES key encrypten met RSA.
		_encryptedAesKey = rsaCipher.encrypt(password.toString(), rsaKeyPair.getPublicKey(), transformation, encoding);
	}

	// lijkt me een overbodige methode ?
	public void generatePrivateRSAKey(RSAKeyPair pair) throws IOException {

		_rsaPair.toFileSystem("Private_A", "Public_A");
		updateLog("Private RSA key generated.");


		_RSAPrivateKey = rsaKeyPair.getPrivateKey();
	}

	// lijkt me een overbodige methode ?
	public void generatePublicRSAKey(RSAKeyPair pair) {

		updateLog("Public RSA key generated.");

		_RSAPublicKey = rsaKeyPair.getPublicKey();
	}

	//File_1 wordt aangemaakt.
	public void encryptFile(File file) throws StrongEncryptionNotAvailableException, IOException {
		InputStream input = new FileInputStream(file);
		OutputStream output = new FileOutputStream(new File("File_1"));
		_aes.encryptFile(KeyLength.ONE_TWENTY_EIGHT, password, input, output);
		_encryptedFilesExist = true;
		updateLog("File encrypted with symmetric key.");
	}
	
	public void hashSymmetricEncryptedFile() throws Exception {
		Path path = Paths.get(symmetricEncryptedFile.getAbsolutePath());
		byte[] data = Files.readAllBytes(path);
		_hashSymmetricEncryptedFile = Hash.getHash(data);
		System.out.println("Hash of encrypted file: " + _hashSymmetricEncryptedFile);
		updateLog("Hash of symmetric encrypted file is now created.");
	}

	public void encryptSymmetricKey() {
		/*
		 * 
		 * 
		 * TODO Encrypt symmetric key code.
		 */
		updateLog("Symmetric key is now encrypted.");
	}

	public void hashOriginalFile(File file) throws Exception {
		Path path = Paths.get(file.getAbsolutePath());
		byte[] data = Files.readAllBytes(path);
		_hashOriginalFile = Hash.getHash(data);
		System.out.println("Hash of original file: " + _hashOriginalFile);
		updateLog("Hash of original file is now created.");

	}
	/* De encrypted hash deel 1 pakket */
	public void encryptHash() throws IOException, GeneralSecurityException {
		final String transformation = "RSA/ECB/PKCS1Padding";
	    final String encoding = "UTF-8";
		_encryptedHash = _rsaCipher.encrypt(_hashOriginalFile, _publicKeyServer, transformation, encoding);
		updateLog("Hash of the original file is now encrypted.");
	}
	
	//maakt de client aan
	public void sendFile() {
		Packet filePacket = new Packet(_RSAPublicKey,symmetricEncryptedFile , _encryptedHash, password);
		SSL_Client client = new SSL_Client();
		try {
			client.createClientSocket(filePacket);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		playSound("sendFile.wav");
		updateLog("File sent!");
	}

	public void playSound(String soundName) {
		AudioInputStream audioInputStream;
		URL url = TCPClient.class.getResource("/resources/sendFile.wav");
		try {
			audioInputStream = AudioSystem.getAudioInputStream(url);
			Clip clip = AudioSystem.getClip();
			clip.open(audioInputStream);
			clip.start();
		} catch (UnsupportedAudioFileException | IOException | LineUnavailableException e) {
			e.printStackTrace();
		}
	}
}
