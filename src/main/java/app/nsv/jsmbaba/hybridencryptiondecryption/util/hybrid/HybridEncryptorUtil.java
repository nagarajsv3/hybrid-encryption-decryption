package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import app.nsv.jsmbaba.hybridencryptiondecryption.domain.StudentInfo;
import app.nsv.jsmbaba.hybridencryptiondecryption.util.JsonUtils;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class HybridEncryptorUtil {

    public static String decrypt(String jweString) throws NoSuchAlgorithmException, JOSEException, ParseException, CertificateException, IOException {

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

        String decrypt = RSAOAEPDecryption.decrypt(jweString, rsaPrivateKey);

        return decrypt;


    }

    public static String encrypt(String[] args) throws NoSuchAlgorithmException, JOSEException, ParseException, CertificateException, IOException {

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


        StudentInfo studentInfo = new StudentInfo("Naga","Srinivasa","Leela");

        String message = JsonUtils.convertObjectToString(studentInfo);

        String jweString = RSAOAEPEncryption.encrypt(message, alg, enc, rsaPublicKey, cek, null);

        return jweString;

    }


}
