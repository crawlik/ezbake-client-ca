package ezbake.clientca.cli.commands;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
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
import java.util.Properties;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ezbake.clientca.cli.ClientCACommand;

public class GenerateCertificate extends ClientCACommand {

    //--------------------------------------------------------------------------------
    // main entry point

    @Override
    public void run() {
        configure();

        // These are kept separate in order to make it simpler, in the
        // future, to allow users to generate their own signing
        // requests and submit them to this CA.

        writeRequest();
        writeCert();
    }
    
    //--------------------------------------------------------------------------------
    // config

    private void configure() {
        loadProperties();
        cacertFile = propertyOrDie("client-ca.cacert.file");
        cakeyFile = propertyOrDie("client-ca.cakey.file");
        cakeyPass = config.getProperty("client-ca.cakey.pass");
        csrFile = config.getProperty("client-ca.csr.file", principalName + ".csr");
        userKeyFile = config.getProperty("client-ca.userkey.file", principalName + ".key");
    }

    //--------------------------------------------------------------------------------
    // configurable fields

    private String cacertFile;
    private String cakeyFile;
    private String cakeyPass;
    private String csrFile;
    private String userKeyFile;

    @Option(name="-u", aliases={"--user"}, usage="FreeIPA user name to create a certificate for", required=true)
    public String principalName;
    
    @Option(name="-c", aliases={"--config"}, usage="Java properties config file")
    public String propsFile = "/opt/ezbake/client-ca/config/client-ca.properties";

    @Option(name="-o", aliases={"--out"}, usage="output cert file")
    private String certFile = "-";

    @Option(name="-d", aliases={"--"}, usage="certificate TTL in days")
    public long certTTLDays;

    //--------------------------------------------------------------------------------

    private void writeRequest() {
        try {
            KeyPair pair = randomKeyPair();
            PKCS10CertificationRequest req = getReq(pair);
            writePEM(pair.getPrivate(), writer(userKeyFile));
            writePEM(req, writer(csrFile));
        } catch (OperatorCreationException | GeneralSecurityException | IOException | CryptoException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    //--------------------------------------------------------------------------------

    private void writeCert() {
        try {
            writePEM(
                     signCSR(
                             readPEM(csrFile, PKCS10CertificationRequest.class),
                             readPEM(cacertFile, X509CertificateHolder.class),
                             new JcaPEMKeyConverter()
                             .setProvider("BC")
                             .getKeyPair(
                    
                                         (cakeyPass != null)

                                         ?

                                         readPEM(cakeyFile, PEMEncryptedKeyPair.class)
                                         .decryptKeyPair(new JcePEMDecryptorProviderBuilder()
                                                         .build(cakeyPass.toCharArray())) 

                                         :

                                         readPEM(cakeyFile, PEMKeyPair.class)),

                             expiryDate(System.currentTimeMillis()),
                             randomSerial()),
                     writer(certFile));
        } catch (OperatorCreationException | CryptoException | IOException | CertException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    //--------------------------------------------------------------------------------

    private PKCS10CertificationRequest getReq(KeyPair pair)
        throws IOException, CryptoException, GeneralSecurityException, OperatorCreationException {

        SubjectPublicKeyInfo publicKey = 
                        SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        return new PKCS10CertificationRequestBuilder(x500Name(principalName), publicKey).build(contentSigner(pair));
    }

    //--------------------------------------------------------------------------------

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
            csr.getSubjectPublicKeyInfo()
        ).build(contentSigner(cakeys));

        if (!cert.isSignatureValid(new JcaContentVerifierProviderBuilder()
                                   .setProvider("BC")
                                   .build(cakeys.getPublic()))) {
            throw new CryptoException("signature not valid for " + 
                                      cert + " against keys " + cakeys);
        }

        return cert;
    }

    //--------------------------------------------------------------------------------
    // utility functions to generate certificate fields

    private ContentSigner contentSigner(KeyPair keys)
        throws OperatorCreationException, CryptoException {
        return new JcaContentSignerBuilder(signatureAlgorithm(keys.getPublic().getAlgorithm()))
            .setProvider("BC")
            .build(keys.getPrivate());
    }

    private Date expiryDate(long now) {
        long certTTLMillis = certTTLDays * 3600 * 1000;
        return new Date(now + certTTLMillis);
    }

    private String signatureAlgorithm(String algorithm)
        throws CryptoException {
        String sigAlg = ALGORITHMS.get(algorithm);
        if (sigAlg != null) {
            return sigAlg;
        } else {
            throw new CryptoException("Algorithm " + algorithm + " is neither DSA nor RSA");
        }
    }

    private KeyPair randomKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private BigInteger randomSerial() {
        return new BigInteger(63, RANDOM);
    }
    
    private X500Name x500Name(String user) throws IOException {
        String hostname = InetAddress.getLocalHost().getHostName();
        String[] hostElements = hostname.split("\\.");
        logger.trace("{}: got {} components for hostname {}", user, hostElements.length, hostname);
                
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
        logger.trace("broke domain into {} components", hostElements.length);
        for (int i = hostElements.length - 1; i > 0; i--) {
            String element = hostElements[i];
            logger.trace("adding domain dc={} to {}", element, user);
            builder.addRDN(RFC4519Style.dc, element);
        }
        builder.addRDN(RFC4519Style.cn, "accounts");
        builder.addRDN(RFC4519Style.cn, "users");
        builder.addRDN(RFC4519Style.uid, user);
        return builder.build();
    }

    private final SecureRandom RANDOM = new SecureRandom();

    //--------------------------------------------------------------------------------
    // config helpers

    private void loadProperties() {
        config = new Properties();
	try {
	    config.load(new FileReader(new File(propsFile)));
	} catch (IOException e) {
	    logger.error("problem loading {}", propsFile);
	    System.exit(1);
	}
    }

    private String propertyOrDie(String prop) {
        String result = config.getProperty(prop);
	if (result == null) {
	    throw new RuntimeException("could not find required property " + prop);
	}
	return result;
    }

    private Properties config;

    //--------------------------------------------------------------------------------
    // available algorithms

    private static Map<String, String> ALGORITHMS;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ALGORITHMS = new HashMap<String,String>();
        ALGORITHMS.put("DSA", "SHA1withDSA");
        ALGORITHMS.put("RSA", "SHA1withRSAEncryption");
    }

    //--------------------------------------------------------------------------------
    // PEM IO

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

    private void writePEM(Object obj, Writer writer) throws IOException {
        JcaPEMWriter pw = new JcaPEMWriter(writer);
        pw.writeObject(obj);
        pw.close();
    }
    
    private Writer writer(String maybeFile) throws IOException {
        switch (maybeFile) {
        case "-": return new OutputStreamWriter(System.out);
        default: return new FileWriter(maybeFile);
        }
    }

    //--------------------------------------------------------------------------------
    // logger

    Logger logger = LoggerFactory.getLogger(GenerateCertificate.class);

}
