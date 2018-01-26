package digitalsignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class DigitalSignature {
    
    public static void main(String[] args) throws Exception{
       //System.out.println( Paths.get(".").toAbsolutePath().normalize().toString()); ** get working directory path
       byte[] file = Files.readAllBytes(new File ("test.txt").toPath());
       CipherMethods.printFileContent("test.txt");
       
       //instanciar o gerador de chaves e gerar uma chave
       KeyGenerator keygen = KeyGenerator.getInstance("AES");
       SecretKey key = keygen.generateKey();
       
       
       CipherMethods.cipherFile("test.txt", key);
       CipherMethods.decipherFile("enc.txt", key);
       
       CipherMethods.digestFile("test.txt");
       
    }
    
}
