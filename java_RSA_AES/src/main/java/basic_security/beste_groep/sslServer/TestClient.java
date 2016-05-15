package basic_security.beste_groep.sslServer;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import basic_security.beste_groep.controller.Packet;
import basic_security.beste_groep.encryption.RSAKeyPair;

public class TestClient {

	public static void main(String[] args) {
		SSL_Client c = new SSL_Client();
		try {
			RSAKeyPair keys = new RSAKeyPair(2064);
			
			c.createClientSocket(new Packet(keys.getPublicKey(), new File("File_1"), "Pxl", "hello"));
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		/*try {
			c.writeToSocket("Hello world");
		}
		catch (IOException e) {
			System.out.println("Client");
			System.out.println(e);
		}
		
		//c.closeClientSocket();// TODO Auto-generated method stub */

	}

}
