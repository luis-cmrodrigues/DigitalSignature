package digitalsignature;

import AuxiliaryClasses.EmptyKeyException;
import AuxiliaryClasses.UsrInput;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class DigitalSignature {

    public static void main(String[] args) throws Exception {
        Scanner userInput = new Scanner(System.in);

        //instanciar o gerador de chaves e gerar uma chave
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        SecretKey key = keygen.generateKey();

        System.out.println("Selecione uma das implementacoes");
        System.out.println("1 -- java.crypto");
        System.out.println("2 -- bouncyCastle");

        switch (UsrInput.readInt(userInput)) {
            case 1:
                CryptoImplementation(userInput, key);
                break;
            case 2:
                BouncyImplementation(userInput, key);
                break;
            default:
                break;
        }

        userInput.close();
    }

    private static void CryptoImplementation(Scanner userInput, SecretKey key) throws IOException, InvalidKeyException {
        //System.out.println( Paths.get(".").toAbsolutePath().normalize().toString()); ** get working directory path
        CryptoMethods.printFileContent("test.txt");

        CryptoMethods.cipherFile("test.txt", key);
        CryptoMethods.decipherFile("enc.txt", key);

        CryptoMethods.digestFile("test.txt");
    }

    private static void BouncyImplementation(Scanner userInput, SecretKey key) throws IOException, EmptyKeyException, InvalidCipherTextException {
        //byte[] keyBytes = key.toString();
        byte[] keyBytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(key.getEncoded()));
        byte[] out = null;

        System.out.println("Assine e verifique a assinatura com um destes digests:");
        System.out.println("1 -- sha1");
        System.out.println("2 -- sha256");
        System.out.println("3 -- sha512");
        System.out.println("4 -- md5");

        switch (UsrInput.readInt(userInput)) {
            case 1:
                BouncyMethods.cipherStream(BouncyMethods.digestFile("sha1", "test.txt"), keyBytes, null);
                BouncyMethods.decipherStream("DigSig_sha1.txt", keyBytes, null);
                BouncyMethods.verificaHash();
                break;
            case 2:
                BouncyMethods.digestFile("sha256", "test.txt");
                break;
            case 3:
                BouncyMethods.digestFile("sha512", "test.txt");
                break;
            case 4:
                BouncyMethods.digestFile("md5", "test.txt");
                break;
            default:
                break;
        }

        //BouncyMethods.printFileContent("test.txt");
    }

}
