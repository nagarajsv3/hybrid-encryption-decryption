package app.nsv.jsmbaba.hybridencryptiondecryption.service;

import app.nsv.jsmbaba.hybridencryptiondecryption.domain.StudentRequest;
import app.nsv.jsmbaba.hybridencryptiondecryption.util.hybrid.HybridEncryptorUtil;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.text.ParseException;

import static app.nsv.jsmbaba.hybridencryptiondecryption.util.JsonUtils.convertObjectToString;

@Service
public class HybridEncryptorService {


    public String encrypt(String message) throws CertificateException, IOException, NoSuchProviderException {



        return null;
    }

    public String add(StudentRequest studentRequest) throws JOSEException, CertificateException, NoSuchAlgorithmException, ParseException, IOException {

        decryptEncryptedData(studentRequest);


        return convertObjectToString(studentRequest) ;

    }

    private void decryptEncryptedData(StudentRequest studentRequest) throws IOException, CertificateException, NoSuchAlgorithmException, ParseException, JOSEException {
        String encryptedData = studentRequest.getEncryptedData();
        String decrypt = HybridEncryptorUtil.decrypt(encryptedData);
        System.out.println("decrypt"+decrypt);
    }




}
