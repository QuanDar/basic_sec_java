package basic_security.beste_groep.Hash;

import java.security.MessageDigest;			//Standaard Library Java
import org.apache.commons.codec.binary.Hex; //comon-codec
/**
 * 
 * @author Steven Deuss 16/03/2016
 *
 */
public class Hash {
	
	
	/**
	 * We zetten het wachtwoord om naar een hash. We maken gebruik van het SHA-256 algorithm
	 * We kunnen deze methode verder uitbreiden met een salt.
	 * @param password Is wachtwoord dat meegeven ingeven wordt
	 * @return een string representatie van het hashed wachtwoord
	 * @throws Exception Hiermee vangen we de NoSuchAlgorithm mee op
	 */
	public static String getHash(byte[] data) throws Exception {
		/* De messageDigest is de class binnen java die Hashing voorziet.
		 * De mogelijke algorithms vinden we terug in Java Crytography achitecture Standard algorithm documentatie.
		 */
		//Hier halen we een MessageDigest object op, die het SHA-256 algorithm gebruikt.
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		//De update methode zal het object updaten met de gegeven bytes. In dit geval een byte array
		md.update(data);
		
		//Met de digest methode voltooien we het hashen. Deze methode geeft een byte array terug		
		byte[] digestedBytes = md.digest();
		
		/* Vervolgens gaan we de byte array omzetten naar een hexadecimale string representaite
		 * We maken hier gebruik van de common-codec library van apache. Zie pom bestand voor de depency
		 */
		String hexHash = Hex.encodeHexString(digestedBytes); //Methode van de common-codec library
		
		//We geven het hashed wachtwoord terug
		return hexHash;
	}
	
	
}