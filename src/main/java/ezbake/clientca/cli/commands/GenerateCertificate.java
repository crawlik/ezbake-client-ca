package ezbake.clientca.cli.commands;

import ezbake.clientca.cli.ClientCACommand;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import org.kohsuke.args4j.Option;

public class GenerateCertificate extends ClientCACommand {
    private static Map<String, String> ALGORITHMS = new HashMap() {{  
        put("DSA", "SHA1withDSA");
        put("RSA", "SHA1withRSAEncryption");
    }}

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

    @Override
    public void run() {
        System.out.println("principal name: " + principalName);
        X509CertificateHolder cert = signCSR(
                readPEM(csrFile, PKCS10CertificationRequest.class),
                readPEM(cacertFile, X509CertificateHolder.class),
                new JcaPEMKeyConverter().setProvider("BC").getKeyPair(

                    (cakeyPass != null)  
                  
                    ?

                    readPEM(cakeyFile, PEMEncryptedKeyPair.class)
                        .decryptKeyPair(new JcePEMDecryptorProviderBuilder()
                                            .build(cakeyPass)) 

                    :

                    readPEM(cakeyFile, PEMKeyPair.class)));

	System.out.write(cert.getBytes(), 0, cert.getBytes().size);
    }

    public X509CertificateHolder signCSR(PKCS10CertificationRequest csr, 
                                   X509CertificateHolder cacert,
                                   KeyPair cakeys,
                                   Date endDate,
                                   BigInteger ser)
        throws CryptoException, IOException {

        X509CertificateHolder cert = new X509v3CertificateBuilder(
            cacert.getSubject(),
            ser,
            new Date(),
            endDate,
            csr.getCertificationRequestInfo().getSubject(),
            cacert.getSubjectPublicKeyInfo()
        ).build(
            new JcaContentSignerBuilder(getSignatureAlgorithm(cakeys.getPublic().getAlgorithm())
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

    private <T> T readPEM(String filename, Class<T> klass)
        throws IOException, CryptoException {
        PEMParser pemParser = new PEMParser(new FileReader(filename));
        Object pemObject = pemParser.readObject();
        if (pemObject instanceof T) {
            return (T)pemObject;
        } else {
            throw new CryptoException("trouble reading csr " + filename + 
                                      ": object " + pemObject + 
                                      " of wrong type " + pemObject.getClass());
        }
    }

    public void getSignatureAlgorithm(String algorithm) 
        throws CryptoException {
        String sigAlg = ALGORITHMS.get(algorithm);
        if (sigAlg != null) {
            return sigAlg;
        } else {
            throw new CryptoException("Algorithm " + algorithm + " is neither DSA nor RSA");
        }
    }
}
