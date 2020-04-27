import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        String s = in.nextLine();
        String privateloc = "RSA/"+s+".xml";
        String publicloc = "RSA/"+s+"pub.xml";


        KeyPair keyPair = KeyGenerator.createKeyPair(1024);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String privateKeyAsXml = KeyGenerator.getPrivateKeyAsXml(privateKey);
        KeyGenerator.writeFile(privateKeyAsXml,privateloc);
        String publicKeyAsXml = KeyGenerator.getPublicKeyAsXml(publicKey);
        KeyGenerator.writeFile(publicKeyAsXml,publicloc);


    }
}
