package basic_security.beste_groep.sslServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.net.ssl.SSLSocket;

import basic_security.beste_groep.controller.Packet;

/* Source
 * https://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
 */
public class SSLServerThread extends Thread
{
	
	private SSLSocket sslSocket;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	public SSLServerThread(SSLSocket sslSocket,PrivateKey privateKey, PublicKey publicKey) {
        super("MultiServerThread");
        this.sslSocket = sslSocket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
	
	public void run() {
		try (	OutputStream _sslOS = sslSocket.getOutputStream(); 	//De outputstream voor gegevens weg te schrijven naar de client
				InputStream _sslIS = sslSocket.getInputStream();	//De inputstream om gegevens in te lezen vanuit de client
				//Dit stuk is wat de server met de conection doet. Dit moet verder aangepast worden aan de noden
				
				ObjectOutputStream out = new ObjectOutputStream(_sslOS))
		{
			out.writeObject(publicKey);
			
			ObjectInputStream in = new ObjectInputStream(_sslIS);
			Packet Input;
			boolean recieved = false;
			while ( !recieved) {
				Input = (Packet) in.readObject();
				System.out.println(Input.toString());
				System.out.flush();			//Gegevens door de stream puche
				recieved = true;
			}
				
			sslSocket.close();
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
