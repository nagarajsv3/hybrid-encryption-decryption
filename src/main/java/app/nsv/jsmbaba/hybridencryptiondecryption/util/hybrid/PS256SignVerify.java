package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class PS256SignVerify {

    public static void main(String[] args) throws JOSEException, ParseException, NoSuchAlgorithmException {


        //Add Bouncy Castle a318b757-1020-4a1c-9cb4-4edd1ca0ca07 Security Provider
        Security.addProvider(new BouncyCastleProvider());

        solution2();
        //solution1();

    }


    public static String signingProcess(RSAPrivateKey rsaPrivateKey, String jwe) throws JOSEException {

        Security.addProvider(new BouncyCastleProvider());

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaPrivateKey);

// Prepare JWS object with simple string a318b757-1020-4a1c-9cb4-4edd1ca0ca07 payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.PS256).build(),
                new Payload(jwe));

// Compute the RSA signature
        jwsObject.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String jws = jwsObject.serialize();
        System.out.println("JWS="+jws);
        return jws;
    }

    public static void signverification(RSAPublicKey rsaPublicKey, String jws) throws JOSEException, ParseException {

        Security.addProvider(new BouncyCastleProvider());

        JWSObject jwsObject = JWSObject.parse(jws);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);

        System.out.println(jwsObject.verify(verifier));

        System.out.println("In RSA we trust!"+ jwsObject.getPayload().toString());
    }


    private static void solution1() throws JOSEException, ParseException {
        // RSA signatures require a public and private RSA key pair,
// the public key must be made known to the JWS recipient to
// allow the signatures to be verified
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

// Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

// Prepare JWS object with simple string a318b757-1020-4a1c-9cb4-4edd1ca0ca07 payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(rsaJWK.getKeyID()).build(),
                new Payload("In RSA we trust!"));

// Compute the RSA signature
        jwsObject.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String s = jwsObject.serialize();

// To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);

        System.out.println(jwsObject.verify(verifier));

        System.out.println("In RSA we trust!" + jwsObject.getPayload().toString());
    }

    private static void solution2() throws JOSEException, ParseException, NoSuchAlgorithmException {
        // RSA signatures require a public and private RSA key pair,
// the public key must be made known to the JWS recipient to
// allow the signatures to be verified
        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

// Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaPrivateKey);

// Prepare JWS object with simple string a318b757-1020-4a1c-9cb4-4edd1ca0ca07 payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.PS256).build(),
                new Payload("In RSA we trust!"));

// Compute the RSA signature
        jwsObject.sign(signer);

// To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String s = jwsObject.serialize();

// To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);

        System.out.println(jwsObject.verify(verifier));

        System.out.println("In RSA we trust!" + jwsObject.getPayload().toString());
    }
}
