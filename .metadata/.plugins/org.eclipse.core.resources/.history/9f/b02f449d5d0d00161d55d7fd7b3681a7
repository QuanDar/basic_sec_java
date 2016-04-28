package basicSecurity_SSL;

import java.security.KeyStoreException;

public class TestServer {
	
	final static String keystorelocation = "/src/main/resources/TrustStoreBasicSuc";
	final static String pwdKeystore = "Steven";
	//static boolean debuging = false;

	
	public static void main(String[] args) {
		
		//Setting properties for keystore
		//System.setProperty("javax.net.ssl.keyStore",keystore);
		//System.setProperty("javax.net.ssl.keyStorePassword",pwdKeystore);
		
		SSL_Server s = new SSL_Server();
		//s.createServerSocket();
		try {
			s.createServerSocket();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
		
	}

}
