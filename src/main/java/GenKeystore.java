import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyPair;

//Source : http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.html
//		   http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.PrivateKeyEntry.html
//         http://stackoverflow.com/questions/10956956/using-rsa-encryption-in-java-without-bouncycastle



public class GenKeystore {

	public static void main(String[] args) throws Exception {

		//Création du keystore.
		KeyStore ks = KeyStore.getInstance("jks");

		//Mot de passe.
		char[] password = {'1', '2', '3', '4', '5', '6'};
		KeyStore.PasswordProtection protected_password = new KeyStore.PasswordProtection(password);
	
		//Chargement à partir de rien (creation du keystore).
		ks.load(null, password);

		/*
		//Création de la clef privée.
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
       										ks.getEntry("privateKeyAlias", protected_password);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		*/

		//Création de la paire de clef.
		KeyPairGenerator key_gen = KeyPairGenerator.getInstance("RSA");		
		key_gen.initialize(1048);
		KeyPair keys = key_gen.genKeyPair();
		byte[] private_key = keys.getPrivate().getEncoded(); //clef privée encodé.

		//Sauvegarde de la clef privée.
		//KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(keys.getPrivate());

		/*
		//Sauvegarde de la clef privée.
		javax.crypto.SecretKey my_secret_key; //= new levraiquifaitleschose(); //on doit la créer ici ?
    	KeyStore.SecretKeyEntry sk_entry = new KeyStore.SecretKeyEntry(my_secret_key);
    	ks.setEntry("secretKeyAlias", sk_entry, protected_password);
		*/
/*
	 void	setKeyEntry(String alias, byte[] key, Certificate[] chain) 
          Assigns the given key (that has already been protected) to the given alias.
 void	setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) 
          Assigns the given key to the given alias, protecting it with the given password.
*/

    }
}
