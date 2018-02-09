package digitalsignature;

import AuxiliaryClasses.EmptyKeyException;
import AuxiliaryClasses.UsrInput;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
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

        System.out.println("Selecione uma das opcoes");
        System.out.println("1 -- java.crypto");
        System.out.println("2 -- bouncyCastle");
        //System.out.println("Gerar um par de chaves");

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

    private static void BouncyImplementation(Scanner userInput, SecretKey key) throws IOException, EmptyKeyException, InvalidCipherTextException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException {
        //byte[] keyBytes = key.toString();
        byte[] keyBytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(key.getEncoded()));
        byte[] out = null;
        
        KeyStoreManager keyManager = new KeyStoreManager();

        System.out.println("Assine e verifique a assinatura com uma destas arquiteturas:");
        System.out.println("1 -- Criptografia de chave simetrica");
        System.out.println("2 -- Criptografia de chave publica");
        System.out.println("3 -- imprime o certificado e as chaves");

        switch (UsrInput.readInt(userInput)) {
            case 1:
                BouncyMethods.cipherStreamSimmetricKey(BouncyMethods.digestFile("test.txt"), keyBytes, null);
                BouncyMethods.decipherStreamSimmetricKey("DigSig_sha1.txt", keyBytes, null);
                BouncyMethods.verificaHash();
                break;
            case 2:
                BouncyMethods.verifySignature("test.txt", BouncyMethods.signFilePKIX("test.txt", keyManager), keyManager);
                break;
            case 3:
                KeyStoreManager.teste();
                break;
            default:
                break;
        }

        //BouncyMethods.printFileContent("test.txt");
    }

}
