/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package digitalsignature;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Parte que trabalhar com a java keytool e obtem as chaves a partir de um ficheiro keystore
 *
 * Atencao: os parametros definidos servem apenas para a keystore na diretoria do projeto
 * 
 * @author Luis Rodrigues
 */

public class KeyStoreManager {

    private static PublicKey pKey = null;
    private static PrivateKey sKey = null;
    //private static DSAPrivateKey dsaSecretKey = null;
    //private static DSAPublicKey dsaPublicKey = null;
    private static X509Certificate x590cert = null;

    public KeyStoreManager() {
        try {
            setUp();
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyStoreManager.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("ERROR: problema a inicializar o objeto");
        }
    }

    public PublicKey getpKey() {
        return pKey;
    }

    public PrivateKey getsKey() {
        return sKey;
    }

//    public DSAPrivateKey getDsaSecretKey() {
//        return dsaSecretKey;
//    }

//    public DSAPublicKey getDsaPublicKey() {
//        return dsaPublicKey;
//    }

    public X509Certificate getX590cert() {
        return x590cert;
    }

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
        System.out.println();

        //   ---  guarda as chaves para ficheiros
        //Files.write(new File("secretKey.pem").toPath(), getPrivateKey().getEncoded());
        //Files.write(new File("publicKey.pem").toPath(), getPublicKey().getEncoded());
        //NOTA: tipo de certificado = x509
        // obter os parametros do certificado diretamente
        X509Certificate crt = (X509Certificate) ks.getCertificate("client");

        DSAPrivateKey dsaSk = (DSAPrivateKey) myPrivateKey;
        DSAPublicKey dsaPk = (DSAPublicKey) myPublicKey;

        DSAKey dKey = (DSAKey) myPublicKey;
        DSAParams keyParams = dKey.getParams();

        BigInteger sKeyValue = dsaSk.getX();
        System.out.println("Valor da chave privada X: " + sKeyValue);

        BigInteger pKeyValue = dsaPk.getY();
        System.out.println("Valor da chave publica Y: " + pKeyValue);

        BigInteger keyBase = keyParams.getG();
        System.out.println("Valor da base da chave G: " + keyBase);

        BigInteger keyPrime = keyParams.getP();
        System.out.println("Valor do  primo P: " + keyPrime);

        BigInteger keySubPrime = keyParams.getQ();
        System.out.println("Valor do  sub primo Q: " + keySubPrime);

    }

    /**
     * constroi um keypair partindo do par de chaves publica e privada
     *
     * https://docs.oracle.com/javase/7/docs/api/java/security/KeyPair.html#KeyPair(java.security.PublicKey,%20java.security.PrivateKey)
     *
     * @return keyPair
     */
    public KeyPair getKeyPair() throws UnrecoverableEntryException {
        if (pKey == null || sKey == null) {
            try {
                setUp();
            } catch (KeyStoreException | NoSuchAlgorithmException ex) {
                Logger.getLogger(KeyStoreManager.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

        return new KeyPair(pKey, sKey);
    }

    /**
     * inicializa os pares de chaves e o certificado para nao ser preciso estar
     * sempre a chamar as mesmas funcoes
     *
     */
    public void setUp() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        KeyStore ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
        char[] password = "projetolab".toCharArray();
        FileInputStream fis;

        try {
            fis = new FileInputStream("clientkeystore");

            try {
                ks.load(fis, password);
            } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
                Logger.getLogger(KeyStoreManager.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("SET-UP ERROR: problem initializing keystore");
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(KeyStoreManager.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("SET-UP ERROR: file not found");
        }

        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);
        pKey = ks.getCertificate("client").getPublicKey();

        Enumeration<String> alias = ks.aliases();
        java.security.KeyStore.PrivateKeyEntry pkEntry = (java.security.KeyStore.PrivateKeyEntry) ks.getEntry(alias.nextElement(), protParam);
        sKey = pkEntry.getPrivateKey();

        //NOTA: tipo de certificado = x509
        // obter os parametros do certificado diretamente
        x590cert = (X509Certificate) ks.getCertificate("client");

//        dsaSecretKey = (DSAPrivateKey) sKey;
//        dsaPublicKey = (DSAPublicKey) pKey;

        //esta é a parte que permite obter os parametros da chave
        //DSAKey dKey = (DSAKey) pKey;
        //DSAParams keyParams = dKey.getParams();
    }

}
