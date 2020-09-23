package app.nsv.jsmbaba.hybridencryptiondecryption.util;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static app.nsv.jsmbaba.hybridencryptiondecryption.constants.AppConstants.RSA;
import static app.nsv.jsmbaba.hybridencryptiondecryption.constants.AppConstants.RSA_OEAP_256;


@Getter
@Setter
@ToString
public class RSAUtils {


    /*
     *  code to generate the private key from base64 encoded string using PKCS8EncodedKeySpec
     * */
    public static PrivateKey getPrivateKey(String base64EncodedPrivateKey) {
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64EncodedPrivateKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }


    /*
     * X509EncodedKeySpec class to convert public key in X509 format to RSA public key
     * */
    public static PublicKey getPublicKey(String base64EncodedPublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64EncodedPublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * Reads file content and creates a PrivateKey
     *
     * @param filename
     * @return
     * @throws Exception
     */
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey getPrivateKeyFromFile(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    /**
     * Reads file content and creates a PublicKey
     *
     * @param filename
     * @return
     * @throws Exception
     */
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public static PublicKey getPublicKeyFromFile(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(RSA_OEAP_256);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] encrypt(String data, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        return encrypt(data.getBytes(), publicKey);
    }

    public static byte[] encrypt(String data, PublicKey publicKey, String format) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        return encrypt(data.getBytes(format), publicKey);
    }

    /*
     * encrypt()that takes the string to be enrypted and the Base64 encoded RSA key for encryption
     * */
    public static byte[] encrypt(String data, String base64EncodedPublicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        return encrypt(data, getPublicKey(base64EncodedPublicKey));
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA_OEAP_256);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

/*
    https://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privkey, oaepParams);
        */
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String base64EncodedData, String base64EncodedPrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(base64EncodedData.getBytes()), getPrivateKey(base64EncodedPrivateKey));
    }

    public static void encryptFile(byte[] input, File outputFile, PublicKey key) throws IOException, GeneralSecurityException {
        writeToFile(outputFile, encrypt(input, key));
    }

    public static void decryptFile(byte[] input, File outputFile, PrivateKey key)
            throws IOException, GeneralSecurityException {
        writeToFile(outputFile, decrypt(input, key).getBytes());
    }

    private static void writeToFile(File output, byte[] toWrite)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public static byte[] getFileInBytes(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }


}
