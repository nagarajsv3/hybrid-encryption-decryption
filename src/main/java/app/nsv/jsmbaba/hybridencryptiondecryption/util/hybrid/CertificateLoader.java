package app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

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


@Component
public class CertificateLoader {

    @Value("${security.enc.cert}")
    private String encCertPath ;

    @Value("${security.dec.cert}")
    private String decCertPath ;


    public Certificate loadEncryptionCertificate() throws CertificateException, NoSuchProviderException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509","SUN");
        DefaultResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(encCertPath);
        if(null!=resource){
            InputStream inputStream = resource.getInputStream();
            return factory.generateCertificate(inputStream);
        }
        return null;
    }

    public RSAPublicKey getRSAPublicKey() throws CertificateException, IOException {
        String pemEncodedPublicKey = IOUtils.readFileToString(new File(encCertPath), Charset.forName("UTF-8"));
        Base64 base64 = new Base64(
                pemEncodedPublicKey.replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""));
        Certificate cf = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(base64.decode()));
        return (RSAPublicKey) cf.getPublicKey();
    }



}
