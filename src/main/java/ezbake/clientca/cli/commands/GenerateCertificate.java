package ezbake.clientca.cli.commands;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.kohsuke.args4j.Option;

import ezbake.clientca.cli.ClientCACommand;

public class GenerateCertificate extends ClientCACommand {
    private static final SecureRandom RANDOM = new SecureRandom();

	private static Map<String, String> ALGORITHMS;
    static {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	ALGORITHMS = new HashMap<String,String>();
    	ALGORITHMS.put("DSA", "SHA1withDSA");
    	ALGORITHMS.put("RSA", "SHA1withRSAEncryption");
    }

    @Option(name="-ca", usage="CA Cert to read", required=true)
    public String cacertFile;

    @Option(name="-cakey", usage="CA Cert to read", required=true)
    public String cakeyFile;

    @Option(name="-csr", usage="intermediate CSR file", required=true)
    public String csrFile;

    @Option(name="-privkey", usage="intermediate privkey file", required=true)
    public String keyFile;

    @Option(name="-out", usage="output cert file", required=true)
    private String certFile;

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
    }
    private Date expiry;

    public void setSerial() {
       serial = new BigInteger(63, new SecureRandom());
    }
    
    private BigInteger serial;


    private void writePEM(Object obj, String fileName) throws IOException {
    	FileWriter writer= new FileWriter(fileName);
    	JcaPEMWriter pw = new JcaPEMWriter(writer);
    	pw.writeObject(obj);
    	pw.close();
    }
    
    private void init() {
	System.out.println(cacertFile + "," + cakeyFile + "," + csrFile + "," + certFile);
    	setDate();
    	setSerial();
    }

    private void writeRequest() {
    	try {
			KeyPair pair = randomKeyPair();
			PKCS10CertificationRequest req = getReq(pair);
			writePEM(pair.getPrivate(), keyFile);
			writePEM(req, csrFile);
		} catch (OperatorCreationException | GeneralSecurityException | IOException | CryptoException e) {
			e.printStackTrace();
			System.exit(1);
		}
    }

    private void writeCert() {
    	try {
    		writePEM(
    				signCSR(
    						readPEM(csrFile, PKCS10CertificationRequest.class),
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
    				),
    				certFile);
    	} catch (OperatorCreationException | CryptoException | IOException | CertException e) {
    		e.printStackTrace();
    		return;
    	}
    }

    @Override
    public void run() {
    	init();

    	// TODO: can run writeRequest on client side and authenticate
    	// to server side, which will write cert.
    	writeRequest();
    	writeCert();
    }
    
    private KeyPair randomKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private PKCS10CertificationRequest getReq(KeyPair pair)
    		throws IOException, CryptoException, GeneralSecurityException, OperatorCreationException {
    	X500Name x500Name = getX500Name(principalName);
    	SubjectPublicKeyInfo publicKey = 
    			SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
    	return new PKCS10CertificationRequestBuilder(x500Name, publicKey).build(getContentSigner(pair));
    }

	private X500Name getX500Name(String user) throws IOException {
		String[] hostElements = InetAddress.getLocalHost().getHostName().split(",");
		String[] domainElements = Arrays.copyOfRange(hostElements, 1, hostElements.length);
		
		X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
		for (String element : domainElements) {
			builder.addRDN(RFC4519Style.dc, element);
		}
		builder.addRDN(RFC4519Style.cn, "users");
		builder.addRDN(RFC4519Style.uid, user);
		return builder.build();
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
            getContentSigner(cakeys)
        );

        if (!cert.isSignatureValid(new JcaContentVerifierProviderBuilder()
                                       .setProvider("BC")
                                       .build(cakeys.getPublic()))) {
            throw new CryptoException("signature not valid for " + 
                                      cert + " against keys " + cakeys);
        }

        return cert;
    }

	private ContentSigner getContentSigner(KeyPair keys)
			throws OperatorCreationException, CryptoException {
		return new JcaContentSignerBuilder(getSignatureAlgorithm(keys.getPublic().getAlgorithm()))
		    .setProvider("BC")
		    .build(keys.getPrivate());
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
	    Class actualClass = (pemObject == null) ? null : pemObject.getClass();
            throw new CryptoException("trouble reading csr " + filename + 
                                      ": object " + pemObject + 
                                      " of wrong type " + actualClass);
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
