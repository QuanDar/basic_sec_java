package basic_security.beste_groep.controller;

import java.io.File;
import java.io.Serializable;
import java.security.PublicKey;

public class Packet implements Serializable{
	
	/**
	 * This class is used to wrap all information in 1 single packed.
	 */
	private static final long serialVersionUID = 1L;
	private PublicKey _publicKeyClient;
	private File _encryptedAesFile;
	private String _encryptedeHash;
	private char[] _aesKey;
	
	
	public Packet(PublicKey _publicKeyClient, File _encryptedAesFile, String _encryptedeHash, char[] _AesKey) {
		super();
		this._publicKeyClient = _publicKeyClient;
		this._encryptedAesFile = _encryptedAesFile;
		this._encryptedeHash = _encryptedeHash;
		this._aesKey = _AesKey;
	}
	
	
	public PublicKey get_publicKeyClient() {
		return _publicKeyClient;
	}


	public void set_publicKeyClient(PublicKey _publicKeyClient) {
		this._publicKeyClient = _publicKeyClient;
	}


	public File get_encryptedAesFile() {
		return _encryptedAesFile;
	}


	public void set_encryptedAesFile(File _encryptedAesFile) {
		this._encryptedAesFile = _encryptedAesFile;
	}


	public String get_encryptedeHash() {
		return _encryptedeHash;
	}


	public void set_encryptedeHash(String _encryptedeHash) {
		this._encryptedeHash = _encryptedeHash;
	}


	public char[] get_encryptedAesKey() {
		return _aesKey;
	}


	public void set_encryptedAesKey(char[] _encryptedAesKey) {
		this._aesKey = _encryptedAesKey;
	}


	
	
	
}
