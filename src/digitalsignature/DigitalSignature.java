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
       printFileContent("test.txt");
       
       //instanciar o gerador de chaves e gerar uma chave
       KeyGenerator keygen = KeyGenerator.getInstance("AES");
       SecretKey key = keygen.generateKey();
       
       // instanciar as ciphers
       Cipher c_enc = Cipher.getInstance("AES");
       c_enc.init(Cipher.ENCRYPT_MODE, key);
       
       Cipher c_dec = Cipher.getInstance("AES");
       c_dec.init(Cipher.DECRYPT_MODE, key);
       
       
       //encripta o ficheiro
       byte[] fichEncriptado = c_enc.doFinal(file);
       Files.write(new File("enc.txt").toPath(),fichEncriptado);
       printFileContent("enc.txt");
       
       //decifrar o ficheiro
       // fazer novamente a leitura do ficheiro a decifrar e decifrar
       file = Files.readAllBytes(new File ("enc.txt").toPath());
       byte[] fichDecifrado = c_dec.doFinal(file);
       
       Files.write(new File("dec.txt").toPath(),fichDecifrado);
       printFileContent("dec.txt");
       
       
       
    }
    
    public static void printFileContent(String fileName) throws IOException{
       byte[] file = Files.readAllBytes(new File (fileName).toPath());
       String s = new String (file);
       System.out.println(s);
    }
    
}
