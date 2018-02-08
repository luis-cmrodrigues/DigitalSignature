/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package digitalsignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Certificate;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import org.bouncycastle.asn1.*;

/**
 *
 * @author Luis Rodrigues
 */
public class KeyStoreManager {

    static PublicKey pKey = null;
    static PrivateKey sKey = null;

    /**
     * Imprime o certificado e chave publica e privada As chaves são codificadas
     * no formato ASN
     *
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException
     */
    public static void teste() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        java.security.KeyStore ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());

        FileInputStream fis = new FileInputStream("clientkeystore");
        PrivateKey myPrivateKey = null;

        char[] password = "projetolab".toCharArray();
        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);
        ks.load(fis, password);

        PublicKey myPublicKey = ks.getCertificate("client").getPublicKey();

        Enumeration<String> alias = ks.aliases();

        System.out.println("alias: " + alias.nextElement());
        //obtencao da chave privada contida na keystore
        java.security.KeyStore.PrivateKeyEntry pkEntry = (java.security.KeyStore.PrivateKeyEntry) ks.getEntry(alias.nextElement(), protParam);
        myPrivateKey = pkEntry.getPrivateKey();

        System.out.println("certificado: " + ks.getCertificate("client"));
        System.out.println("public key:  " + BouncyMethods.bytesToHex(myPublicKey.getEncoded()));
        System.out.println("private key: " + BouncyMethods.bytesToHex(myPrivateKey.getEncoded()));

        System.out.println("Atributos da chave privada " + pkEntry.getAttributes().size());

        
        //   ---  guarda as chaves para ficheiros
        //Files.write(new File("secretKey.pem").toPath(), getPrivateKey().getEncoded());
        //Files.write(new File("publicKey.pem").toPath(), getPublicKey().getEncoded());
        

//        Certificate crt = (Certificate) ks.getCertificate("client");
        //      System.out.println("Atributos da chave publica " + ks.getCertificate("client"));
    }

    public static PrivateKey getPrivateKey() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        java.security.KeyStore ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
        FileInputStream fis = new FileInputStream("clientkeystore");
        PrivateKey myPrivateKey = null;

        char[] password = "projetolab".toCharArray();
        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);

        ks.load(fis, password);

        Enumeration<String> alias = ks.aliases();

        //System.out.println("alias: " + alias.nextElement());
        //obtencao da chave privada contida na keystore
        try {
            java.security.KeyStore.PrivateKeyEntry pkEntry = (java.security.KeyStore.PrivateKeyEntry) ks.getEntry(alias.nextElement(), protParam);
            myPrivateKey = pkEntry.getPrivateKey();

            sKey = myPrivateKey;

            //System.out.println("private key: " + BouncyMethods.bytesToHex(myPrivateKey.getEncoded()));
        } catch (UnrecoverableEntryException ex) {
            System.out.println("ERRO: na obtencao da chave");
        }

        return myPrivateKey;

    }

    public static PublicKey getPublicKey() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        java.security.KeyStore ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
        FileInputStream fis = new FileInputStream("clientkeystore");

        char[] password = "projetolab".toCharArray();
        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);

        ks.load(fis, password);

        Enumeration<String> alias = ks.aliases();

        //System.out.println("alias: " + alias.nextElement());
        //obtencao da chave publica a partir do certificado gerado e guardado na keystore
        PublicKey myPublicKey = ks.getCertificate("client").getPublicKey();
        //System.out.println("certificado: " + ks.getCertificate("client"));
        //System.out.println("public key: " + BouncyMethods.bytesToHex(myPublicKey.getEncoded()));

        pKey = myPublicKey;

        return myPublicKey;

    }

    /**
     * constroi um keypair partindo do par de chaves publica e privada
     *
     * https://docs.oracle.com/javase/7/docs/api/java/security/KeyPair.html#KeyPair(java.security.PublicKey,%20java.security.PrivateKey)
     *
     * @return keyPair
     */
    public static KeyPair getKeyPair() {
        if (pKey == null || sKey == null) {
            System.out.println("ATENCAO: uma das chaves encontra-se vazia");
        }

        return new KeyPair(pKey, sKey);
    }

}
