import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Security;
import java.math.BigInteger;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

//Source : http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.html
//	       http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.PrivateKeyEntry.html
//         http://stackoverflow.com/questions/10956956/using-rsa-encryption-in-java-without-bouncycastle
//	       http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation


public class GenKeystore {

	

	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		//Mot de passe.
		char[] password = {'1', '2', '3', '4', '5', '6'};
		KeyStore.PasswordProtection protected_password = new KeyStore.PasswordProtection(password);

		//Création du keystore.
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(null, password);  //Chargement à partir de rien (creation du keystore et non importation).

		//Création de la paire de clef.
		KeyPairGenerator key_gen = KeyPairGenerator.getInstance("RSA");		
		key_gen.initialize(1024);
		KeyPair keys = key_gen.genKeyPair();
		//byte[] private_key = keys.getPrivate().getEncoded(); //clef privée encodé.


		//Création du certificat.
		//ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keys.getPrivate());
		X509V3CertificateGenerator cert_gen = new X509V3CertificateGenerator();

		X500Principal cn = new X500Principal("CN=SXP");
		cert_gen.setSerialNumber(new BigInteger("123456789"));
		cert_gen.setIssuerDN(cn);
		cert_gen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
		cert_gen.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000));
		cert_gen.setSubjectDN(cn);
		cert_gen.setPublicKey(keys.getPublic());
		cert_gen.setSignatureAlgorithm("MD5WithRSA"); //SHA256withRSA

		/*
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,new
		AuthorityKeyIdentifierStructure(caCert));

		//Ca fonctionne pas à cause des type de clef, peut être pas utile.
		cert_gen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		    new SubjectKeyIdentifierStructure( keys.getPublic().getEncoded() ));
		*/

		X509Certificate[] cert_chain = new X509Certificate[1];
		cert_chain[0] = cert_gen.generateX509Certificate(keys.getPrivate(), "BC"); //CA private key (auto signed)

		ks.setEntry("SXP",
				new KeyStore.PrivateKeyEntry(keys.getPrivate(), cert_chain),
				new KeyStore.PasswordProtection(password));


		//Enregistement du keystore dans un fichier.
		java.io.FileOutputStream fos = null;
		try 
		{
			fos = new java.io.FileOutputStream("keystore.jks");
			ks.store(fos, password);
		}
		finally 
		{
			if(fos != null)
				fos.close();
		}


		
    }
}
