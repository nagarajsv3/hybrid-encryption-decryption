package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPublicKey;

public class RSAOAEPEncryption {

    public static String encrypt(String message, JWEAlgorithm alg , EncryptionMethod enc, RSAPublicKey rsaPublicKey, SecretKey cek, String kid) throws JOSEException {
        // Encrypt the JWE with the RSA public key + specified AES CEK

        JWEHeader.Builder jweHeaderBuilder = new JWEHeader.Builder(alg, enc);
        jweHeaderBuilder.keyID(kid);
        jweHeaderBuilder.customParam("iat",System.currentTimeMillis());
        JWEHeader jweHeader = jweHeaderBuilder.build();

        JWEObject jwe = new JWEObject(jweHeader,new Payload(message));
        jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
        String jweString = jwe.serialize();

        System.out.println("encData: JWE="+jweString);
        return jweString;
    }



}
