package basic_security.beste_groep.sslServer;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import basic_security.beste_groep.encryption.RSAKeyPair;

/**
 * This class creates an SSL server  
 * @author Steven Deuss
 *
 */
/*
 * A Java KeyStore (JKS) is a repository of security certificates
 * � either authorization certificates or public key certificates � used for instance in SSL encryption. 
 */
public class SSL_Server {
	
	final static int serverSocket = 12350; 	//Socket nummer die we gebruiken. Dit kan ook meegegeven worden als parameter
	boolean listening = true;				//Deze kunnen op false zetten om de server uit te schakelen
/**
 * This method opens an SSL socket for server use.
 * It listens for any communication to the socket
 * @throws GeneralSecurityException 
 */
	public void createServerSocket() throws GeneralSecurityException {
		try {
			RSAKeyPair keyPair= new  RSAKeyPair(2048);
			PublicKey publicKey = keyPair.getPublicKey();
			PrivateKey privateKey = keyPair.getPrivateKey();
			
			/* Source
			 * http://www.programcreek.com/java-api-examples/javax.net.ssl.KeyManagerFactory
			 * Socket communication (non SSL)
			 * https://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html	
       		 */
			final char[] JKS_PASSWORD = "Steven".toCharArray();		//Wachtwoord van de keystore file
			final char[] KEY_PASSWORD = "Steven".toCharArray();		//Wachtwoord van certificaat
			
				/* Get the JKS contents */
			final KeyStore keyStore = KeyStore.getInstance("JKS");					//Keystore instance aanmaken
			final InputStream is = getClass().getResourceAsStream("KeyStoreBasic"); //inputstream om de keystore uit de recources te lezen
			keyStore.load(is, JKS_PASSWORD);										//Keystore inladen in de instance
				
			/*
			* De keymanager hebben we nodig voor het manegen van het certificaat dat in de keystore zit
			*/
			final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
					.getDefaultAlgorithm());
			kmf.init(keyStore, KEY_PASSWORD); //initialiseren van de manager. Hier hebben we keystore en bijhorend wachtwoord nodig

			/*
			 * Creates a socket factory for SSL conection using JKS
			 * contents
			 */
			 //De contex hebben we nodig om de encrytptie + certificaat te behandelen
			final SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());
			/* Aanmaken van de socket factory voor de server
			 * Dit object gaan we gebruiken om de sockeet aan te makken
			 */
			final SSLServerSocketFactory socketFactory = sc.getServerSocketFactory(); 
			
			/* Source
			 * https://www.youtube.com/watch?v=QUrbNbxG2i0&list=PLrUFyg1unBb-FIokhhW64hYAtSMmazKTY&index=12&feature=iv&annotation_id=annotation_3438798559&src_vid=S2Vxr3RoRgI
			 */
			//Aanmaken van de socket
			SSLServerSocket sslServersocket = (SSLServerSocket) socketFactory.createServerSocket(serverSocket);
			
			/* Source 
			 * Multi threading
			 * https://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
			 */
			while (listening) {
			//Socket instellen om te luisteren of er een verbinding aangevraagd wordt
			SSLSocket _sslSocket = (SSLSocket) sslServersocket.accept();
			//De supported chiphersuites enabelen voor de socket
			_sslSocket.setEnabledCipherSuites(socketFactory.getSupportedCipherSuites());
			new SSLServerThread(_sslSocket, privateKey, publicKey).start();
			
			/*	Wikipedia
			 *	A cipher suite is a collection of symmetric and asymmetric encryption algorithms
			 *	used by hosts to establish a secure communication. Supported cipher suites can be classified based on
			 *	encryption algorithm strength, key length, key exchange and authentication mechanisms.
			 */
			}
			
		}
		catch (SSLHandshakeException e) {
		System.out.println(e);
		System.out.println(e.toString());
		}
		catch (SecurityException e) {
			System.out.println("Connection not allowed!");
			System.out.println(e);
		}
		catch (IOException e) {
			System.out.println(e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}