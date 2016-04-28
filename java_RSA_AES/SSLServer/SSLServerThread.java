package basicSecurity_SSL;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;

public class SSLServerThread extends Thread
{
	SSLSocket sslSocket;
	public SSLServerThread(SSLSocket sslSocket) {
        super("MultiServerThread");
        this.sslSocket = sslSocket;
    }
	
	public void run() {
		try (	OutputStream _sslOS = sslSocket.getOutputStream(); 	//De outputstream voor gegevens weg te schrijven naar de client
				InputStream _sslIS = sslSocket.getInputStream();	//De inputstream om gegevens in te lezen vanuit de client
				//Dit stuk is wat de server met de conection doet. Dit moet verder aangepast worden aan de noden
				BufferedReader in = new BufferedReader(new InputStreamReader(_sslIS)); )
		{
		
			String userInput;
			while ((userInput = in.readLine()) != null) {
				System.out.println(userInput);
				System.out.flush();			//Gegevens door de stream puche
			}
				
			sslSocket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
