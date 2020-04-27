import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.io.PrintWriter;
import java.io.StringWriter;



public class KeyGenerator {
    static final String KEY_ALGORITHM = "RSA";
    static final int KEY_LENGTH = 1024;



    static final String NL = System.getProperty("line.separator");



    static public KeyPair createKeyPair(int keyLength) throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keyLength);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }


    static String getPrivateKeyAsEncoded(PrivateKey privateKey){
        byte[] privateKeyEncodedBytes = privateKey.getEncoded();
        return getBase64(privateKeyEncodedBytes);
    }

    static String getPublicKeyAsEncoded(PublicKey publicKey){
        byte[] publicKeyEncodedBytes = publicKey.getEncoded();
        return getBase64(publicKeyEncodedBytes);
    }


    static String getPrivateKeyAsXml(PrivateKey privateKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec spec = keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        StringBuilder sb = new StringBuilder();

        sb.append("<RSAKeyValue>" + NL);
        sb.append(getElement("Modulus", spec.getModulus()));
        sb.append(getElement("Exponent", spec.getPublicExponent()));
        sb.append(getElement("P", spec.getPrimeP()));
        sb.append(getElement("Q", spec.getPrimeQ()));
        sb.append(getElement("DP", spec.getPrimeExponentP()));
        sb.append(getElement("DQ", spec.getPrimeExponentQ()));
        sb.append(getElement("InverseQ", spec.getCrtCoefficient()));
        sb.append(getElement("D", spec.getPrivateExponent()));
        sb.append("</RSAKeyValue>");

        return sb.toString();
    }

    static String getPublicKeyAsXml(PublicKey publicKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        RSAPublicKeySpec spec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        StringBuilder sb = new StringBuilder();

        sb.append("<RSAKeyValue>" + NL);
        sb.append(getElement("Modulus", spec.getModulus()));
        sb.append(getElement("Exponent", spec.getPublicExponent()));
        sb.append("</RSAKeyValue>");

        return sb.toString();
    }



    static String getElement(String name, BigInteger bigInt) throws Exception{
        byte[] bytesFromBigInt = getBytesFromBigInt(bigInt);
        String elementContent = getBase64(bytesFromBigInt);
        return String.format(" <%s>%s</%s>%s", name, elementContent,name,NL);
    }

    static String getBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }


    static byte[] getBytesFromBigInt(BigInteger bigInt){
        byte[] bytes = bigInt.toByteArray();
        int length = bytes.length;

        if(length % 2 != 0 && bytes[0] == 0){
            bytes = Arrays.copyOfRange(bytes,1,length);
        }
        return bytes;
    }
    static void writeFile(String text, String filename) throws Exception{
        try(PrintWriter writer = new PrintWriter(filename)){
            writer.write(text);
        }
    }



}

