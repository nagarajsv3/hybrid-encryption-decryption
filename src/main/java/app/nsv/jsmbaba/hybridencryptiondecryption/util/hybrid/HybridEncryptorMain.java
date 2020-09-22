package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.IOUtils;

import static sun.security.provider.X509Factory.BEGIN_CERT;
import static sun.security.provider.X509Factory.END_CERT;

public class HybridEncryptorMain {

    public static void main(String[] args) throws NoSuchAlgorithmException, JOSEException, ParseException, CertificateException, IOException {

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey)rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)rsaKeyPair.getPrivate();
        System.out.println("******RSA Keypair Generated******");


        // Generate the Content Encryption (CEK) key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();
        System.out.println("******Content Encryption (CEK) key Generated******");


        String message = "Hi!!! Welcome to Hybrid Encryption" ;

        String jweString = RSAOAEPEncryption.encrypt(message, alg, enc, rsaPublicKey, cek, null);

        String decrypt = RSAOAEPDecryption.decrypt(jweString, rsaPrivateKey);


    }


    /*
     * Converts PEM file content to RSAPublicKey
     * The method getRSAPublicKey() converts PEM file content that is downloaded from VDP to RSAPublicKey as shown below:
     */
    private static RSAPublicKey getRSAPublicKey(String certificatePath) throws CertificateException, IOException {
        String pemEncodedPublicKey = IOUtils.readFileToString(new File(certificatePath), Charset.forName("UTF-8"));
        Base64 base64 = new Base64(
                pemEncodedPublicKey.replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""));
        Certificate cf = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(base64.decode()));
        return (RSAPublicKey) cf.getPublicKey();
    }



}
