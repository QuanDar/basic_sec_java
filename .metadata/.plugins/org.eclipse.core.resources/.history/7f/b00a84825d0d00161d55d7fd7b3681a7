package basicSecurity_SSL;

import java.io.IOException;

public class TestClient {

	public static void main(String[] args) {
		SSL_Client c = new SSL_Client();
		c.createClientSocket();
		
		try {
			c.writeToSocket("Hello world");
		}
		catch (IOException e) {
			System.out.println("Client");
			System.out.println(e);
		}
		
		//c.closeClientSocket();// TODO Auto-generated method stub

	}

}
