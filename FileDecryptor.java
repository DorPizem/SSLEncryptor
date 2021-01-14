import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.function.Supplier;


public class FileDecryptor {

    // Decrypt the AES key using the "Decryptor" private key.
    // This method return the re-stored AES key.
    // args:
    // encryptedKeyPath: The file path to the encrypted key data.
    // algorithm: The algorithm to use for decryption.
    // privateKey: The "Decryptor" private key.
    public SecretKey decryptAESKey(String encryptedKeyPath, String algorithm, PrivateKey privateKey) {
        SecretKey secretKey = null;
        byte[] secretKeyAsBytes;

        try {
            Utils.encryptLogger.info("Starting AES key decryption...");
            Utils.encryptLogger.info("Reading encrypted AES key as bytes from: " + encryptedKeyPath + "...");
            byte[] encryptedKeyAsBytes = Files.readAllBytes(Paths.get(encryptedKeyPath));

            Utils.encryptLogger.info("initialize the cipher with:\n" +
                    "Algorithm: " + algorithm +
                    "\nPrivate Key: " + privateKey);
            Cipher cipher = Cipher.getInstance(Utils.ENCRYPT_SECRET_KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            secretKeyAsBytes = cipher.doFinal(encryptedKeyAsBytes);
            secretKey = new SecretKeySpec(secretKeyAsBytes, 0, secretKeyAsBytes.length, "AES");
            Utils.encryptLogger.info("AES key decryption finish successfully");
        } catch(Exception e) {
            Utils.encryptLogger.info("exception decrypting the aes key: " + e.getMessage());
        } finally {
            return secretKey;
        }
    }

    // Decrypt the file using a given algorithm and an IV
    // This method return void and write the decrypted data into a file
    // args:
    // encryptedFile: The encrypted file path.
    // outputFile: The path to write the decryption result
    // secret key: the AES key for decrypt the file
    // algorithm: which algorithm to use for decryption
    // ivParameterSpec: The IV for decryption
    public void decryptFile(String encryptedFile, String outputFile, SecretKey secretKey, String algorithm, IvParameterSpec ivParameterSpec)
                            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
                                    InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Utils.encryptLogger.info("Initializing Cypher:" +
                "\nMode: " + Cipher.DECRYPT_MODE +
                "\nAlgorithm: " + algorithm +
                "\nKey: " + secretKey);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        Utils.encryptLogger.info("Cipher initialized successfully");
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        Utils.encryptLogger.info("Start decrypting data...");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        Utils.encryptLogger.info("Decrypting data finished successfully. \nSaved to: " + Utils.FILE_TO_DECRYPT_PATH);
        inputStream.close();
        outputStream.close();
        Utils.encryptLogger.info("==================FILE_AFTER_DECRYPTION=============\n" +
                Files.readAllLines(Paths.get(outputFile)));
    }

    // Getting a sign file and the original file and verifies them using the signer public key and the 'Signature' instance
    // This method return TRUE if the sign file is verified.
    // args:
    // signedFilePath: the sign file path.
    // originalFilePath: original file path
    // publicKey: the signer public key
    public boolean verifySignature(String signedFilePath, String originalFilePath, PublicKey publicKey) throws Exception{
        boolean isVerified = false;
        Utils.encryptLogger.info("Reading signature as bytes from: " + signedFilePath);
        byte[] data = Files.readAllBytes(Paths.get(signedFilePath));
        Utils.encryptLogger.info("Initializing signature instance with:\n" +
                        "Algorithm: " + Utils.SIGNATURE_ALGORITHM +
                        "Public Key: " + publicKey);
        Signature signature = Signature.getInstance(Utils.SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(Files.readAllBytes(Paths.get(originalFilePath)));
        Utils.encryptLogger.info("Verifying signature...");
        isVerified = signature.verify(data);
        Utils.encryptLogger.info("Signature verification result = " + isVerified);

        return isVerified;
    }
}
