import java.security.*;
import javax.crypto.Cipher;

public class CoreLedger {
    public KeyPair mintKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }
    public MessageDigest legacyDigest() throws Exception {
        return MessageDigest.getInstance("SHA-1");
    }
    public Cipher batchCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
