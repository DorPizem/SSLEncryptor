import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyExtractor {
    private String keyStorePassword;
    private String alias;
    private String filePath;

    public KeyExtractor(String keyStorePassword, String alias, String filePath) {
        this.keyStorePassword = keyStorePassword;
        this.alias = alias;
        this.filePath = filePath;
    }

    public KeyPair extractKeyPairFromKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                                                        UnrecoverableKeyException, NoSuchProviderException {
        Utils.encryptLogger.info("Get " + this.alias + " keystore file");
        FileInputStream is = new FileInputStream(this.filePath);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, this.keyStorePassword.toCharArray());
        Utils.encryptLogger.info("keystore added successfully from file");

        Utils.encryptLogger.info("Extracting keys...");
        PublicKey publicKey = null;
        Key key = keystore.getKey(this.alias, this.keyStorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = (Certificate) keystore.getCertificate(this.alias);
            // Get public key
            publicKey = cert.getPublicKey();
        }
        Utils.encryptLogger.info("=================PUBLIC_KEY==================");
        Utils.encryptLogger.info(Utils.publicKeyToString(publicKey));
        Utils.encryptLogger.info("=================Private_KEY=================");
        Utils.encryptLogger.info(Utils.privateKeyToString((PrivateKey)key));

        Utils.encryptLogger.info(this.alias + " Key extraction finished successfully");
        // Return a key pair
        return new KeyPair(publicKey, (PrivateKey) key);
    }
}
