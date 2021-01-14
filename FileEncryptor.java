import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.rmi.CORBA.Util;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.List;
import java.util.function.Supplier;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

import static java.nio.file.StandardOpenOption.CREATE;


public class FileEncryptor {
    private IvParameterSpec ivParameterSpec;

    public FileEncryptor() throws IOException {
        initializeLogger();
    }

    private void initializeLogger() throws IOException {
        FileHandler fh, fh2;
        fh = new FileHandler(Utils.LOG_PATH);
        Utils.encryptLogger.addHandler(fh);
        SimpleFormatter formatter = new SimpleFormatter();
        fh.setFormatter(formatter);
    }

    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

    // Encrypt a file using AES key and a given algorithm
    // This method return void and write the encrypted data to a file
    // args:
    // algorithm: Which algorithm and provider to use for encryption.
    // secretKey: The key we would like to use for encryption.
    // fileInputPath: The file we would like to encrypt
    // outputFilePath: The encrypted file location
    public void encrypt(String algorithm, SecretKey secretKey, String inputFilePath, String outputFilePath) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Utils.encryptLogger.info("=================ORIGINAL_FILE================\n" +
                Files.readAllLines(Paths.get(inputFilePath)));
        Utils.encryptLogger.info("Initializing Cypher:" +
                "\nMode: " + Cipher.ENCRYPT_MODE +
                "\nAlgorithm: " + algorithm +
                "\nKey: " + secretKey);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, this.generateIv());
        Utils.encryptLogger.info("Cipher initialized successfully");
        FileInputStream inputStream = new FileInputStream(inputFilePath);
        FileOutputStream outputStream = new FileOutputStream(outputFilePath);

        Utils.encryptLogger.info("Start encrypting data...");
        byte[] buffer = new byte[1024];
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
        Utils.encryptLogger.info("Encrypting data finished successfully. \nSaved to: " + Utils.FILE_TO_WRITE_PATH);
        Utils.encryptLogger.info("=================ENCRYPTED_FILE_AS_BYTES================\n" +
                Files.readAllBytes(Paths.get(outputFilePath)));
        inputStream.close();
        outputStream.close();
    }

    // Creating Random IV using secureRandom option to create "real" random IV
    private IvParameterSpec generateIv() {
        Utils.encryptLogger.info("Start generating IV for the file encryption...");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.ivParameterSpec = new IvParameterSpec(iv);
        Utils.encryptLogger.info("IV created successfully.");
        return this.ivParameterSpec;
    }

    // Generate AES key using the KeyGenerator instance
    public SecretKey generateAESKey() throws NoSuchAlgorithmException {
        Utils.encryptLogger.info("Creating secret AES key...");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Utils.encryptLogger.info("Secret AES key created successfully");
        return generator.generateKey();
    }

    // Encrypt the AES key using a given algorithm using the 'Decrypter' public key.
    // This method return void and write the encrypted key to a file
    // args:
    // algorithm: Which algorithm and provider to use for encryption
    // secretKey: The key we would like to encrypt
    // public key: The public key of the 'Decrypter' to use for the encryption
    public void encryptAESKey(String algorithm, SecretKey secretKey, PublicKey publicKey) {
        Utils.encryptLogger.info("Start encrypting AES secret key...");
        byte[] encryptKey = null;
        try {
            Utils.encryptLogger.info("initialize the cipher with:\n" +
                    "Algorithm: " + algorithm +
                    "\nPublic Key: " + publicKey);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptKey = cipher.doFinal(secretKey.getEncoded());
            Path AESKeyPath = Files.write(Paths.get(Utils.AES_ENCRYPTED_FILE_PATH), encryptKey, CREATE);
            Utils.encryptLogger.info("Writing encrypted AES key to " + AESKeyPath.toString());
        } catch (Exception e) {
            Utils.encryptLogger.severe("exception encoding key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Sign a given file with digital signature using the encryptor private key.
    // This method return void and write the signature to a file
    // args:
    // filePath: the file we would like to sign
    // fileOutPutPath: file output location
    // privateKey: The encryptor private key to sign the file with
    public void signFile(String filePath, String fileOutputPath, PrivateKey privateKey) throws Exception {
        Utils.encryptLogger.info("Read plainText as bytes from: " + filePath);
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        Utils.encryptLogger.info("Start Signing file using " +
                "\nAlgorithm: " + Utils.SIGNATURE_ALGORITHM +
                "\nPrivate key: " + privateKey);
        Signature privateSignature = Signature.getInstance(Utils.SIGNATURE_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(fileBytes);
        byte[] signature = privateSignature.sign();

        Files.write(Paths.get(fileOutputPath), signature, CREATE);
        Utils.encryptLogger.info("File sign successfully, written to: " + fileOutputPath);
    }
}
