/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package digitalsignature;

import static digitalsignature.CryptoMethods.printFileContent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implementacao da assinatura digital com a biblioteca BouncyCastle
 *
 * @author Luis Rodrigues
 */
public class BouncyMethods {

    public static void cipherFile(String fileName, byte[] key, byte[] iv) throws IOException, InvalidCipherTextException {
        byte[] fileContent = Files.readAllBytes(new File(fileName).toPath());

        PaddedBufferedBlockCipher encCipher = new PaddedBufferedBlockCipher(new AESEngine());
        KeyParameter kp = new KeyParameter(key);

        encCipher.init(true, new ParametersWithIV(kp, new byte[16]));

        byte[] out = new byte[encCipher.getOutputSize(fileContent.length)];
        
        int len = encCipher.processBytes(fileContent, 0, fileContent.length, out, 0);
        len += encCipher.doFinal(out, len);
        
        
    }

    /**
     * calculo do digest de um ficheiro usando a bib BouncyCastle
     *
     * @param hashFunction digest a usar
     * @param fileName nome do ficheiro
     * @throws IOException
     */
    public static void digestFile(String hashFunction, String fileName) throws IOException {
        Digest d;
        byte[] fileContent = Files.readAllBytes(new File(fileName).toPath());

        switch (hashFunction) {
            case "sha1":
                d = new SHA1Digest();
                break;
            case "sha256":
                d = new SHA256Digest();
            case "sha512":
                d = new SHA512Digest();
                break;
            case "md5":
                d = new MD5Digest();
                break;
            default:
                System.out.println("warning: BouncyMethods: default digest value - sha1");
                d = new SHA1Digest();
                break;
        }

        d.reset();
        d.update(fileContent, 0, fileContent.length);
        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        String hashHex = bytesToHex(hash);
        Files.write(new File("digest.txt").toPath(), hashHex.getBytes());
        printFileContent("digest.txt");

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
     * converte um hash em byte[] para uma String em hexadecimal
     *
     * @param hash variavel byte[]
     * @return String em hex. do input
     */
    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
