package ezbake.clientca.cli.commands;

import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kohsuke.args4j.Option;
import ezbake.clientca.cli.ClientCACommand;

public class GenerateCertificate extends ClientCACommand {
    private static Map<String, String> ALGORITHMS;
    static {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	ALGORITHMS = new HashMap<String,String>();
    	ALGORITHMS.put("DSA", "SHA1withDSA");
    	ALGORITHMS.put("RSA", "SHA1withRSAEncryption");
    }

    @Option(name="-ldaphost", usage="ldap host", required=true)
    public String ldapHost;

    @Option(name="-ldapport", usage="ldap port", required=true)
    public int ldapPort;

    @Option(name="-ldappass", usage="ldap pass", required=true)
    public String ldapPass;

    @Option(name="-ca", usage="CA Cert to read", required=true)
    public String cacertFile;

    @Option(name="-cakey", usage="CA Cert to read", required=true)
    public String cakeyFile;

    @Option(name="-csr", usage="CSR to read", required=true)
    public String csrFile;

    @Option(name="-principal", usage="User principal to create a certificate for", required=true)
    public String principalName;

    @Option(name="-keypass", usage="password for certificate authority key")
    public String cakeyPass;
    
    @Option(name="-expiry", usage="expiration time")
    public String expiryString;

    private void setDate() {
    	if (expiryString == null) {
    		expiry = new Date(System.currentTimeMillis() + 3600 * 24 * 365);
    	} else {
	    DateFormat df = new SimpleDateFormat("EEE MMM dd kk:mm:ss z yyyy", Locale.ENGLISH);
	    try {
    		expiry = df.parse(expiryString);
	    } catch (ParseException e) {
    		expiry = new Date(System.currentTimeMillis() + 3600 * 24 * 365);
	    }
	}

	System.err.println("expiry: " + expiry);
    }
    private Date expiry;

    @Option(name="-serial", usage="serial number")
    public String serialString = "0";

    public void setSerial() {
       serial = new BigInteger(serialString);
    }
    
    private BigInteger serial;

    @Override
    public void run() {
    	setDate();
    	setSerial();

        X509CertificateHolder cert = null;
		try {
			PKCS10CertificationRequest req = getReq();
			System.exit(1);
			cert = signCSR(
			        req,
			        readPEM(cacertFile, X509CertificateHolder.class),
			        new JcaPEMKeyConverter().setProvider("BC").getKeyPair(

			            (cakeyPass != null)
			          
			            ?

			            readPEM(cakeyFile, PEMEncryptedKeyPair.class)
			                .decryptKeyPair(new JcePEMDecryptorProviderBuilder()
			                                    .build(cakeyPass.toCharArray())) 

			            :

			            readPEM(cakeyFile, PEMKeyPair.class)),
			        expiry,
			        serial
			);
			System.out.write(cert.getEncoded(), 0, cert.getEncoded().length);
		} catch (OperatorCreationException | CryptoException | IOException | CertException e) {
			e.printStackTrace();
			return;
		}
    }

    private PKCS10CertificationRequest getReq() throws IOException {
    	String ldapName = "cn=users,cn=accounts,dc=platform,dc=infochimps";
    	//String ldapCreds = "secret";
    	LdapConnectionConfig config = new LdapConnectionConfig();
    	config.setLdapHost(ldapHost);
    	config.setLdapPort(ldapPort);
    	config.setName(ldapName);
    	//config.setCredentials(ldapPass);
    	DefaultPoolableLdapConnectionFactory factory = 
    			new DefaultPoolableLdapConnectionFactory( config );
    	LdapConnectionPool pool = new LdapConnectionPool( factory );
    	pool.setTestOnBorrow(true);
    	
    	LdapConnection connection;
		try {
			connection = new LdapNetworkConnection(ldapHost, ldapPort);
			//connection.bind("cn=users,cn=accounts,dc=platform,dc=infochimps", ldapPass);
			connection.bind();
			//EntryCursor cursor = connection.search( "uid=jbro", "(objectclass=*)", SearchScope.ONELEVEL );
			EntryCursor cursor = connection.search("cn=users,cn=accounts,dc=platform,dc=infochimps", "(uid=jbro)", SearchScope.ONELEVEL);
			//org.apache.directory.api.ldap.model.cursor.SearchCursor cursor = connection.search(new org.apache.directory.api.ldap.model.message.SearchRequestImpl().setFilter("uid=jbro"));

			while ( cursor.next() )
			{
			    Entry entry = cursor.get();
			    System.out.println(entry);
			}
		} catch (LdapException | CursorException e) {
			throw new IOException(e);
		}
    	
    	connection.close();
    	return null;
	}



	private X509CertificateHolder signCSR(PKCS10CertificationRequest csr, 
                                   X509CertificateHolder cacert,
                                   KeyPair cakeys,
                                   Date endDate,
                                   BigInteger ser)
        throws CryptoException, IOException, OperatorCreationException, CertException {

        X509CertificateHolder cert = new X509v3CertificateBuilder(
            cacert.getSubject(),
            ser,
            new Date(),
            endDate,
            csr.getSubject(),
            cacert.getSubjectPublicKeyInfo()
        ).build(
            new JcaContentSignerBuilder(getSignatureAlgorithm(cakeys.getPublic().getAlgorithm()))
                .setProvider("BC")
                .build(cakeys.getPrivate())
        );

        if (!cert.isSignatureValid(new JcaContentVerifierProviderBuilder()
                                       .setProvider("BC")
                                       .build(cakeys.getPublic()))) {
            throw new CryptoException("signature not valid for " + 
                                      cert + " against keys " + cakeys);
        }

        return cert;
    }

    @SuppressWarnings("unchecked")
    private <T> T readPEM(String filename, Class<T> klass)
        throws IOException, CryptoException {
        PEMParser pemParser = new PEMParser(new FileReader(filename));
        Object pemObject = pemParser.readObject();
        pemParser.close();
        if (klass.isInstance(pemObject)) {
            return (T)pemObject;
        } else {
            throw new CryptoException("trouble reading csr " + filename + 
                                      ": object " + pemObject + 
                                      " of wrong type " + pemObject.getClass());
        }
    }

    public String getSignatureAlgorithm(String algorithm) 
        throws CryptoException {
        String sigAlg = ALGORITHMS.get(algorithm);
        if (sigAlg != null) {
            return sigAlg;
        } else {
            throw new CryptoException("Algorithm " + algorithm + " is neither DSA nor RSA");
        }
    }
}
