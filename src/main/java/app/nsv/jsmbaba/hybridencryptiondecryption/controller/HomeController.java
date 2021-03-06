package app.nsv.jsmbaba.hybridencryptiondecryption.controller;

import app.nsv.jsmbaba.hybridencryptiondecryption.domain.StudentRequest;
import app.nsv.jsmbaba.hybridencryptiondecryption.service.HybridEncryptorService;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.text.ParseException;

@RestController
public class HomeController {

    @Autowired
    private HybridEncryptorService service ;

    @RequestMapping(value = "/encrypt", method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public String encrypt(@RequestBody String message) throws CertificateException, IOException, NoSuchProviderException {
        //return "{\"name\":\"Naga\"}";
        return service.encrypt(message);

    }

    @RequestMapping(value = "/student", method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public String addStudent(@RequestBody StudentRequest studentRequest) throws CertificateException, IOException, NoSuchProviderException, ParseException, JOSEException, NoSuchAlgorithmException {
        return service.add(studentRequest);
    }

}
