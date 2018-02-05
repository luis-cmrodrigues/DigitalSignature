package digitalsignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DigitalSignature {

    public static void main(String[] args) throws Exception {

        //instanciar o gerador de chaves e gerar uma chave
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        SecretKey key = keygen.generateKey();

        System.out.println("Selecione uma das implementacoes");
        System.out.println("1 -- java.crypto");
        System.out.println("2 -- bouncyCastle");

        switch (UsrInput.readInt()) {
            case 1:
                //System.out.println( Paths.get(".").toAbsolutePath().normalize().toString()); ** get working directory path
                CryptoMethods.printFileContent("test.txt");

                CryptoMethods.cipherFile("test.txt", key);
                CryptoMethods.decipherFile("enc.txt", key);

                CryptoMethods.digestFile("test.txt");
                break;

            case 2:
                BouncyImplementation();
                break;
            default:
                break;
        }

    }

    private static void BouncyImplementation() throws IOException {
        System.out.println("Introuduza o nome do digest a usar");
        System.out.println("1 -- sha1");
        System.out.println("2 -- sha256");
        System.out.println("2 -- sha512");
        System.out.println("2 -- md5");

        switch (UsrInput.readInt()) {
            case 1:
                BouncyMethods.digestFile("sha1", "test.txt");
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

        BouncyMethods.printFileContent("test.txt");

    }

}

