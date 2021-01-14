# SSLEncryptor
This is a program to encrypt and decrypt text files, executing the SSL protocol using the JavaCrypto library.

 General program flow and guidelines
Generating Key stores and certificates:
  •	Create Keystore for both sides A(encryptor) & B(Decryptor).
  •	Create Encryptor and Decryptor.
Encryption:
Sign the file:
  •	Sign the file using Side A private key from the keystore.
  •	Save the sign data into config file.
Creating the Symmetric key for A-symmetric transfer using RSA method:
  •	Create private random AES key.
  •	Get the public key of Side B.
  •	Encrypt the AES key with side B public key -> save to conf file.
File Encryption:
  •	Initialize the cipher with AES CBC mode and generate random IV.
  •	Use the AES key to encrypt the file.
Decryption:
  •	Decrypt the symmetric key from the file using side B private key from the keystore.
  •	Decrypt the file using the symmetric key above.
  •	Verify the sign data using the side A certificate public key from the keystore
    And create new file with the decrypt data if the data is verified.
