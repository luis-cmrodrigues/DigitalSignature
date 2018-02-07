/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package digitalsignature;

import static com.oracle.jrockit.jfr.ContentType.StackTrace;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
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
import org.bouncycastle.crypto.signers.DSASigner;

/**
 * Implementacao da assinatura digital com a biblioteca BouncyCastle
 *
 * @author Luis Rodrigues
 */
public class BouncyMethods {

    static byte[] hashOriginal;
    static byte[] hashDecifrado;

    /**
     * cifra um digest com a chave fornecida usando AES
     *
     * @param hash digest a cifrar
     * @param key chave a usar para cifrar o digest
     * @param iv vetor de inicializacao
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    public static void cipherStreamSimmetricKey(byte[] hash, byte[] key, byte[] iv) throws IOException, InvalidCipherTextException {

        PaddedBufferedBlockCipher encCipher = new PaddedBufferedBlockCipher(new AESEngine());
        KeyParameter kp = new KeyParameter(key);

        if (iv == null) {
            encCipher.init(true, kp);
        } else {
            encCipher.init(true, new ParametersWithIV(kp, new byte[16]));
        }

        System.out.println("hash.length" + hash.length);
        System.out.println("encCipher.getOutputSize(hash.length)" + encCipher.getOutputSize(hash.length));
        byte[] out = new byte[encCipher.getOutputSize(hash.length)];

        int len;
        len = encCipher.processBytes(hash, 0, hash.length, out, 0);
        len += encCipher.doFinal(out, len);

        out = Base64.getEncoder().encode(out);

        Files.write(new File("DigSig_sha1.txt").toPath(), out);
        //System.out.println(bytesToHex(out));
        System.out.println("Digest cifrado");

    }

    /**
     * decifra o ficheiro e retorna o digest que la esta - usa chave simetrica
     *
     * @param fileName nome do ficheiro
     * @param key chave SIMETRICA a usar a decifrar
     * @param iv vetor de inicializacao
     * @return
     */
    public static byte[] decipherStreamSimmetricKey(String fileName, byte[] key, byte[] iv) throws IOException, DataLengthException, InvalidCipherTextException {
        byte[] fileContent = Files.readAllBytes(new File(fileName).toPath());
        fileContent = Base64.getDecoder().decode(fileContent);

        //PaddedBufferedBlockCipher decCipher = new PaddedBufferedBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher decCipher = new PaddedBufferedBlockCipher(new AESEngine());
        KeyParameter kp = new KeyParameter(key);

        if (iv == null) {
            decCipher.init(false, kp);
        } else {
            decCipher.init(false, new ParametersWithIV(kp, new byte[16]));
        }

        System.out.println(decCipher.getOutputSize(fileContent.length) + "  ---  " + decCipher.getUpdateOutputSize(fileContent.length) + "  ---  " + decCipher.getBlockSize());

        byte[] out = new byte[decCipher.getOutputSize(fileContent.length)];         //  decCipher.getBlockSize()

        System.out.println("Decipher needs " + out.length);
//byte[] out = new byte[decCipher.getUpdateOutputSize(fileContent.length)+decCipher.getBlockSize()];         //  decCipher.getBlockSize()

        //offset para o doFinal
        int len;
        len = decCipher.processBytes(fileContent, 0, fileContent.length, out, 0);
        len += decCipher.doFinal(out, len);
        System.out.println("len is " + len);

        byte[] result = new byte[len];
        System.arraycopy(out, 0, result, 0, len);

        System.out.println("result length is now " + result.length);

        hashDecifrado = out;
        System.out.println("hash contido no ficheiro: " + bytesToHex(result));
        return out;
    }

    
    /**
     * nota: ver https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/DSA.html#method_summary
     * @param fileName
     * @param key
     * @throws IOException 
     */
    public static void cipherStreamPKIX(String fileName, PrivateKey key) throws IOException {
        byte[] hash = digestFile(fileName);
        
        DSASigner signer = new DSASigner();
        signer.init(true, null);
        BigInteger[] vals = null;
        
        
        try {
            vals =(BigInteger[]) signer.generateSignature(hash);

            /*for (BigInteger val : vals) {
                System.out.println();

            }*/
        } catch (NullPointerException e) {
            System.out.println("cipherStreamPXIX - ERRO: null pointer exception");
        }

    }

    /**
     * calculo do digest de um ficheiro usando a bib BouncyCastle
     *
     * @param hashFunction digest a usar
     * @param fileName nome do ficheiro
     * @return byte[] com o digest
     * @throws IOException
     */
    public static byte[] digestFile(String fileName) throws IOException {
        Digest d;
        byte[] fileContent = Files.readAllBytes(new File(fileName).toPath());

        d = new SHA1Digest();

        d.reset();
        d.update(fileContent, 0, fileContent.length);
        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        //guarda para um ficheiro, nao e necessario
        //String hashHex = bytesToHex(hash);
        //Files.write(new File("digest.txt").toPath(), hashHex.getBytes());
        //printFileContent("digest.txt");
        hashOriginal = hash;
        return hash;

    }

    /**
     * compara dois valores de hash: o original que vem da funcao digestFile e o
     * obtido apos ser corrida a funcao decipherStreamSimmetricKey
     *
     */
    public static void verificaHash() {
        System.out.println("Original - " + bytesToHex(hashOriginal));
        System.out.println("Decifrado - " + bytesToHex(hashDecifrado));
        if (Arrays.equals(hashOriginal, hashDecifrado)) {
            System.out.println("Assinatura verificada");
        } else {
            System.out.println("Assinatura não verificada");
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
     * converte um hash em byte[] para uma String em hexadecimal
     *
     * @param hash variavel byte[]
     * @return String em hex. do input
     */
    public static String bytesToHex(byte[] hash) {
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
