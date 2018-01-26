package digitalsignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.util.Base64.Encoder;

public class CipherMethods {

    /**
     * funcão para cifrar um ficheiro na diretoria do projeto
     *
     * @param c Cipher instanciada em modo de encriptacao
     * @param key chave para cifar
     * @param fileName nome do ficheiro a encriptar
     * @throws IOException
     */
    public static void cipherFile(String fileName, SecretKey key) throws IOException, InvalidKeyException {

        Cipher c;

        try {
            c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, (Key) key);

            byte[] file = Files.readAllBytes(new File(fileName).toPath());
            byte[] fichEncriptado;

            try {
                fichEncriptado = c.doFinal(file);
                Files.write(new File("enc.txt").toPath(), fichEncriptado);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(CipherMethods.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(CipherMethods.class.getName()).log(Level.SEVERE, null, ex);
        }
        printFileContent("enc.txt");
    }

    /**
     * funcao para decifrar o ficheiro na diretoria do projeto
     *
     * @param c Cipher instanciada em modo de encriptacao
     * @param key chave para decifrar
     * @param fileName nome do ficheiro a encriptar
     * @throws IOException
     */
    public static void decipherFile(String fileName, SecretKey key) throws IOException, InvalidKeyException {

        try {

            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.DECRYPT_MODE, (Key) key);

            byte[] file = Files.readAllBytes(new File(fileName).toPath());
            byte[] fichDecifrado;
            try {
                fichDecifrado = c.doFinal(file);
                Files.write(new File("dec.txt").toPath(), fichDecifrado);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(CipherMethods.class.getName()).log(Level.SEVERE, null, ex);
            }

            printFileContent("dec.txt");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(CipherMethods.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * funcao para imprimir o conteudo de um ficheiro
     *
     * @param fileName nome do ficheiro
     * @throws IOException
     */
    public static void printFileContent(String fileName) throws IOException {
        byte[] file = Files.readAllBytes(new File(fileName).toPath());
        String s = new String(file);
        System.out.println(s);
    }

    /**
     * calcula o message digest de um ficheiro e imprime o resultado para um
     * ficheiro
     *
     * @param fileName nome do ficheiro para que queremos calcular o digest
     * @throws IOException
     */
    public static void digestFile(String fileName) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] file = Files.readAllBytes(new File(fileName).toPath());
            byte[] test = Base64.getEncoder().encode(md.digest(file));
            byte[] digest = Base64.getDecoder().decode(test);
            Files.write(new File("digest.txt").toPath(), digest);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("ERROR: Digest does NOT exist ");
        }
        printFileContent("digest.txt");

    }

}
