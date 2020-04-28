import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SHA256RSA {

    public static void main(String[] args) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        String input = "";

        String strPK = "";

        String base64Signature = signSHA256RSA(input, strPK);

        System.out.println("Signature = " + base64Signature);

    }

    private static String signSHA256RSA(String input, String strPK) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
        String realPK = strPK.replaceAll("-----END PRIVATE KEY-----", "")
                            .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                            .replaceAll("\n", "");

        byte[] b1 = Base64.getDecoder().decode(realPK);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(input.getBytes("UTF-8"));

        byte[] s = privateSignature.sign();

        return Base64.getEncoder().encodeToString(s);

    }
}
