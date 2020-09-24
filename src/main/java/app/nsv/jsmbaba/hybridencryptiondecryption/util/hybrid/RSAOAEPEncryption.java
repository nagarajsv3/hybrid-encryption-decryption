package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPublicKey;

public class RSAOAEPEncryption {

    public static String encrypt(String message, JWEAlgorithm alg , EncryptionMethod enc, RSAPublicKey rsaPublicKey, SecretKey cek, String kid) throws JOSEException {


        //Form JWE Header
        JWEHeader jweHeader = buildJWEHeader(alg, enc, kid);

        //Form JWEObject
        JWEObject jwe = new JWEObject(jweHeader,new Payload(message));

        // Encrypt the JWE with the RSA public key + specified AES CEK
        jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));

        //Compact Serialization
        String jweString = jwe.serialize();

        System.out.println("JWE="+jweString);
        return jweString;
    }

    private static JWEHeader buildJWEHeader(JWEAlgorithm alg, EncryptionMethod enc, String kid) {
        JWEHeader.Builder jweHeaderBuilder = new JWEHeader.Builder(alg, enc);
        jweHeaderBuilder.keyID(kid);
        jweHeaderBuilder.type(JOSEObjectType.JOSE);
        jweHeaderBuilder.customParam("iat",System.currentTimeMillis());
        return jweHeaderBuilder.build();
    }


}
