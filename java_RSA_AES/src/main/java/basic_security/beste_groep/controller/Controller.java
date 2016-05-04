package basic_security.beste_groep.controller;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.UnsupportedAudioFileException;
import javax.swing.JTextPane;

import basic_security.beste_groep.view.TCPClient;

public class Controller {

	private JTextPane log;
	private boolean encryptedFilesExist;

	public Controller(JTextPane tp) {
		this.log = tp;
	}

	public void updateLog(String text) {
		log.setText(log.getText() + text + "\n");
	}

	public void generateSymmetricKey(String type) {
		/*
		 * TODO Symmetric key code.
		 */
		updateLog("Symmetric " + type + " key generated.");
	}

	public void generateRSAKeys() {
		if (encryptedFilesExist) {
			/*
			 * 
			 * 
			 * TODO Encrypted files deletion code.
			 */
			updateLog("Previous encrypted files are now deleted because new keys were generated.");
		}
		generatePrivateRSAKey();
		generatePublicRSAKey();
	}

	public void generatePrivateRSAKey() {
		/*
		 * 
		 * 
		 * TODO Private RSA key code.
		 */
		updateLog("Private RSA key generated.");
	}

	public void generatePublicRSAKey() {
		/*
		 * 
		 * 
		 * TODO Public RSA key code.
		 */
		updateLog("Public RSA key generated.");
	}

	public void encryptFile(File f) {
		/*
		 * 
		 * 
		 * TODO Encrypt file code.
		 */
		encryptedFilesExist = true;
		updateLog("File encrypted with symmetric key.");
	}

	public void encryptSymmetricKey() {
		/*
		 * 
		 * 
		 * TODO Encrypt symmetric key code.
		 */
		updateLog("Symmetric key is now encrypted.");
	}

	public void hashOriginalFile() {
		/*
		 * 
		 * 
		 * TODO Hash original file code.
		 */
		updateLog("Original file is now hashed.");

	}

	public void encryptHash() {
		/*
		 * 
		 * 
		 * TODO Encrypt hash code.
		 */
		updateLog("Hash of the original file is now encrypted.");
	}

	public void sendFile() {
		/*
		 * 
		 * 
		 * TODO Send file code.
		 */
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
