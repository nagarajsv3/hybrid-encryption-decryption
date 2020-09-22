package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;

import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;

public class RSAOAEPDecryption {

    public static String decrypt(String jweString, RSAPrivateKey rsaPrivateKey) throws ParseException, JOSEException {
        // Decrypt the JWE with the RSA private key
        JWEObject jwe = JWEObject.parse(jweString);
        jwe.decrypt(new RSADecrypter(rsaPrivateKey));
        System.out.println(("Decrypted Payload"+jwe.getPayload().toString()));
        return jwe.getPayload().toString();
    }
}
