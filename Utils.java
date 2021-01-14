import sun.misc.BASE64Encoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

public class Utils {
    public static final String CYPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String ENCRYPT_SECRET_KEY_ALGORITHM = "RSA";
    public static final String SIDEA_KEYSTORE_FILE_PATH = "encrypt.jks";
    public static final String SIDEB_KEYSTORE_FILE_PATH = "decrypt.jks";
    public static final String FILE_TO_READ_PATH = "plaintext.txt";
    public static final String FILE_TO_WRITE_PATH = "encryptedData.txt";
    public static final String FILE_TO_DECRYPT_PATH = "decrypted.txt";
    public static final String AES_ENCRYPTED_FILE_PATH = "conf_AESKey.txt";
    public static final String FILE_SIGNATURE_PATH = "conf_fileSignature.txt";
    public static final String LOG_PATH = "Log.log";

    public static final String KEYSTORE_PASSWORD = "123321";

    public static final Logger encryptLogger = Logger.getLogger("EncryptLog");

    public static String publicKeyToString(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(publicKeyBytes);
    }
    public static String privateKeyToString(PrivateKey privateKey) {
        byte[] privateKeyBytes = privateKey.getEncoded();
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(privateKeyBytes);
    }

    public static void writeKeysToLog(KeyPair keyPair){
        Utils.encryptLogger.info("======ENCRYPT_PUBLIC=======\n" + keyPair.getPublic().toString());
        Utils.encryptLogger.info("======ENCRYPT_PRIVATE=======" + keyPair.getPrivate().toString() + "\n\n");
    }
}
