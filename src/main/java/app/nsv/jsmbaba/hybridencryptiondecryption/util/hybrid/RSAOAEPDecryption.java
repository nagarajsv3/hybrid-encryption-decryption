package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;

import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Base64;

public class RSAOAEPDecryption {

    public static String decrypt(String jweString, RSAPrivateKey rsaPrivateKey) throws ParseException, JOSEException {
        // Decrypt the JWE with the RSA private key
        JWEObject jwe = JWEObject.parse(jweString);
        jwe.decrypt(new RSADecrypter(rsaPrivateKey));
        System.out.println(("Decrypted Payload"+jwe.getPayload().toString()));
        System.out.println(("Decrypted : JWE Header="+jwe.getHeader()));
        System.out.println(("Decrypted : JWE Encrypted Key="+jwe.getEncryptedKey()));
        System.out.println(("Decrypted : JWE IV="+jwe.getIV()+"Base64 Decode="+ jwe.getIV().decodeToString()));
        System.out.println(("Decrypted : JWE CipherText="+jwe.getCipherText()));
        System.out.println(("Decrypted : JWE AuthTag="+jwe.getAuthTag()));

        return jwe.getPayload().toString();
    }
}
