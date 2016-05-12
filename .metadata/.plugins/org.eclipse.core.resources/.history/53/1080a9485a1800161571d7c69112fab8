package basic_security.beste_groep.sslServer;
/*
 * Import list
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SSL_Client {
	//Socket on which the program comunicates
	final static int serversocket = 12350; //Deze kunnen we meegeven als parameter
	final char[] JKS_PASSWORD = "Steven".toCharArray();
	
	//Client side socket + in- and outputstreams
	private SSLSocket sslsocket = null;
	private OutputStream sslOS = null;
	private InputStream sslIS = null;
	
	//Test variabelen
	private String _serverName = "127.0.0.1"; //Deze kunnen we meegeven als parameter
		
	/**
	 * This method opens an ssl socket for client use.
	 */
		public void createClientSocket() {
			/* Source
			 * http://www.programcreek.com/java-api-examples/javax.net.ssl.KeyManagerFactory	
       		 */
			try {
				/* Get the JKS contents */
				final KeyStore keyStore = KeyStore.getInstance("JKS");			            //Keystore instance aanmaken
				final InputStream is = getClass().getResourceAsStream("TrustStoreBasicSuc");//inputstream om de keystore uit de recources te lezen
				keyStore.load(is, JKS_PASSWORD);											//Keystore inladen in de instance
					
				/*  Trustmanager aanmaken. Deze regeld welke certificaten betrouwbaar zijn.
				 *  De standaard trustmanager bevat verschillende CA. Maar omdat we hier gebruik maken van een selfsigned
				 *  certificaat gaan we zelf een trusstore aanmaken om de defualt te overiden */
				final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
						.getDefaultAlgorithm());
				tmf.init(keyStore); //initialiseren van de keystore (truststore)

				/*
				 * Creates a socket factory for SSL conection using JKS
				 * contents
				 */
				//De contex hebben we nodig om de encrytptie + vertrouwen te behandelen
				final SSLContext sc = SSLContext.getInstance("TLS");
				sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
				/* Aanmaken van de socket factory voor de client
				 * Dit object gaan we gebruiken om de sockeet aan te makken
				 */
				final SSLSocketFactory socketFactory = sc.getSocketFactory(); 
				
				//Aanmaken van de socket
				sslsocket = (SSLSocket) socketFactory.createSocket(_serverName,serversocket);
				sslsocket.setEnabledCipherSuites(socketFactory.getSupportedCipherSuites());
				
				//Stream voor het lezen vanuit de socket
				sslIS = sslsocket.getInputStream();
				
				//Stream voor het schrijven naar de socket
				sslOS = sslsocket.getOutputStream();
				
				//Dit stuk is wat de server met de conection doet. Dit moet verder aangepast worden aan de noden
				writeToSocket("hello");
				closeClientSocket();
			}
			catch (SSLHandshakeException e) {
				System.out.println(e);
				System.out.println(e.toString());
			}
			catch (IOException e) {
				System.out.println(e);
			} catch (KeyManagementException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		/**
		 * This method closes the socket and the socket streams
		 */
		public void closeClientSocket() {
			if (sslsocket != null) {
				try {
					sslIS.close();
					sslOS.close();
					sslsocket.close();
				} catch (IOException e) {
					System.out.println(e);
				}
				sslIS = null;
				sslOS = null;
				sslsocket = null;
			}
		}
		
		
		public void writeToSocket(String userInput) throws IOException {
			//hier maken we gebruik van de flush om de stream inhoud weg te schrijven
			if (sslOS != null) {
				try 
				(BufferedWriter out = new BufferedWriter(new OutputStreamWriter(sslOS))) 
				{
					out.write(userInput); 
					out.flush();
					System.out.println("output");
					
				}
			}
		}
		
		
		public void readFromSocket(String serverReply) throws IOException {
			if (sslIS != null) {
				try 
				(BufferedReader in = new BufferedReader(new InputStreamReader(sslIS))) 
				{
					while ((serverReply = in.readLine()) != null) {
						System.out.println(serverReply);
					}
				}
			}
		}
}
