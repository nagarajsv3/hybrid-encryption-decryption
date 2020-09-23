package app.nsv.jsmbaba.hybridencryptiondecryption.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class StudentRequest {
    private String school;

    private String encryptedData ;

    private EncryptedData decryptedData;

}
