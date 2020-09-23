package app.nsv.jsmbaba.hybridencryptiondecryption.util;

import app.nsv.jsmbaba.hybridencryptiondecryption.domain.EncryptedData;
import app.nsv.jsmbaba.hybridencryptiondecryption.domain.StudentRequest;
import com.google.gson.Gson;

public class JsonUtils {

    public static String convertObjectToString(Object studentRequest) {
        Gson gson = new Gson();
        return gson.toJson(studentRequest);
    }

    public static EncryptedData convertStringtoObject(String message) {
        Gson gson = new Gson();
        return gson.fromJson(message, EncryptedData.class);
    }

}
