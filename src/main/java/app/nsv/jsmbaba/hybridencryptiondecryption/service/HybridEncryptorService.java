package app.nsv.jsmbaba.hybridencryptiondecryption.service;

import app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid.CertificateLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

@Service
public class HybridEncryptorService {

    @Autowired
    CertificateLoader certificateLoader;

    public String encrypt(String message) throws CertificateException, IOException, NoSuchProviderException {

        //RSAPublicKey rsaPublicKey = certificateLoader.getRSAPublicKey();
        Certificate certificate = certificateLoader.loadEncryptionCertificate();
        System.out.println(certificate);


        return null;
    }

}
