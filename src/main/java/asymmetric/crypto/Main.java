package asymmetric.crypto;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static asymmetric.crypto.KeyGeneration.generateRSAKkeyPair;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    public static void main(String args[]) throws Exception
    {
        KeyPair keypair = generateRSAKkeyPair();
        logger.info("Keypair generated, key size is 4096");
        String sourceUser = "ye@tidal.com";
        String targetUser= "kim@tidal.com";
        byte[] cipherText = AsymmetricCrypto.encrypt(sourceUser, keypair.getPublic());
        logger.info("Source user is encrypted with public key, cipher text: " + DatatypeConverter.printHexBinary(cipherText));
        byte[] cipherText2 = AsymmetricCrypto.encrypt(targetUser, keypair.getPublic());
        logger.info("Target user is encrypted with public key, cipher test: " + DatatypeConverter.printHexBinary(cipherText2));
        String plaintext = AsymmetricCrypto.decrypt(cipherText, keypair.getPrivate());
        logger.info("Decrypted source user with private key, plaintext: " + plaintext);
        String plaintext2 = AsymmetricCrypto.decrypt(cipherText2, keypair.getPrivate());
        logger.info("Decrypted target user with private key, plaintext: " + plaintext2);

    }
}
