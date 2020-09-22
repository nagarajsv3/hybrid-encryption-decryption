package app.nsv.jsmbaba.hybridencryptiondecryption.controller;

import app.nsv.jsmbaba.hybridencryptiondecryption.service.HybridEncryptorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

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


}
