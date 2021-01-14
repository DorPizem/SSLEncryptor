import javax.crypto.SecretKey;
import java.security.KeyPair;


public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length > 1) {
            System.out.println("Too many args.");
        } else if (args.length < 1) {
            System.out.println("Missing args.");
        } else {
            FileEncryptor fileEncryptor = new FileEncryptor();
            FileDecryptor fileDecryptor = new FileDecryptor();

            KeyExtractor encryptorKeyExtractor = new KeyExtractor(args[0], "encrypt", Utils.SIDEA_KEYSTORE_FILE_PATH);
            KeyExtractor decryptorKeyExtractor = new KeyExtractor(args[0], "decrypt", Utils.SIDEB_KEYSTORE_FILE_PATH);
            KeyPair encryptorKeyPair = encryptorKeyExtractor.extractKeyPairFromKeyStore();
            KeyPair decryptorKeyPair = decryptorKeyExtractor.extractKeyPairFromKeyStore();
            Utils.writeKeysToLog(encryptorKeyPair);
            Utils.writeKeysToLog(decryptorKeyPair);

            SecretKey secretAESKey = fileEncryptor.generateAESKey();
            fileEncryptor.encrypt(Utils.CYPHER_ALGORITHM, secretAESKey, Utils.FILE_TO_READ_PATH, Utils.FILE_TO_WRITE_PATH);
            fileEncryptor.encryptAESKey(Utils.ENCRYPT_SECRET_KEY_ALGORITHM, secretAESKey, decryptorKeyPair.getPublic());
            fileEncryptor.signFile(Utils.FILE_TO_READ_PATH, Utils.FILE_SIGNATURE_PATH, encryptorKeyPair.getPrivate());

            boolean isFileSignatureVerified = fileDecryptor.verifySignature(Utils.FILE_SIGNATURE_PATH, Utils.FILE_TO_READ_PATH, encryptorKeyPair.getPublic());
            if (isFileSignatureVerified) {
                SecretKey secretKey = fileDecryptor.decryptAESKey(Utils.AES_ENCRYPTED_FILE_PATH, Utils.ENCRYPT_SECRET_KEY_ALGORITHM, decryptorKeyPair.getPrivate());
                fileDecryptor.decryptFile(Utils.FILE_TO_WRITE_PATH, Utils.FILE_TO_DECRYPT_PATH, secretKey, Utils.CYPHER_ALGORITHM, fileEncryptor.getIvParameterSpec());
            } else {
                System.out.println("WARNING - Signature is corrupted");
            }
        }
    }
}
