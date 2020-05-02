import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class SHA256RSA {

    private final static String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEA" +
            "AoIBAQCpyNSRb8sZTsOW\nqbhKvQ8/v/XSXKSdn3lBXfUgb5P+rX5L2p8MY5ONvOpVBaUpYmAm5f5QLn1fDdOf\nen6ERTdIQMGlRbeCtNH" +
            "KWRCF1s/loDHapl3nsvu78OHCvoHDsGMsRtTThAYq6jXk\nRLjd6fsUBlMV3IC8XxctNUl8/DrHtSyionLOJfiLp1lD2C7DadeFOwvTOdWo" +
            "qFE0\nqMg3L3jnd3vl+zo3otnoldYXtUO0AWpjgjqyk/QG/pEVFD9fmLIUpY9X9W4avrPw\nV74dPLI3mE/xzeGR9KzJFOAYQE1Cz1kgSsL" +
            "fMeOQP8BlWWsO6sBw8/zNWLZV2naQ\nyxk522VrAgMBAAECggEAMwuRuR4SwkuXazsgkLvRk1mLtxCqX0dcZcYxVeyl4opX\nr8eNTOS9Ln5" +
            "vN1uooc4VWWyJbqLjh4n5J3flBLBoo/zwG1fgCdiCQGNRn+OLAp8M\njg+5qNj7bTBJN8sd6W8lCeFLyEHntsxOoo/0wqc/mPAj161BOSEfr" +
            "zRXoU+V/odg\n+xb667jWc7mceuxVUtX86etdR/VZH3JSzgyEZ1fZpWLhXutqqelC8NdItMnxYqT1\ntWksPwH7N2wFdXvNyU3kD3EmdCcxE" +
            "e3H77+zkkdVpgHz3F8p6WW/Qxm3tiWW9JJD\n6gHFwh8I+sR+bFAPnzQZiRAAH6iihkylnMrqrd47ZQKBgQDVxA8cBq2gJ90Vxd7a\noJOI" +
            "crDJzy56bZ9oZxwtYbUluPLk1GRMkFjncLGeFMhry9Xhnbn4a+PN2zCwj4c/\n61SmBErGhFP6yQ/+qez+kz8PSqA73nk+JM9B6nDix482YK" +
            "oY5SZymlJ04PnGWbSU\nQi8utmPnsbf8BdkoCDAlWi2GLwKBgQDLVENeiiXpTwHw2iO1FbQ9LsufAZmeMnyC\nBsi1kxNlxw6xGHPSOnG2hO" +
            "GUp4HXJvcjD8OFYxtB32Q8UilcSPWI1YpzAasJPuxN\nJTZqkUzixf8Tn4BKNjYZEExynUKDsB1VBAMCkW2OqXxIjKQruPfRxGrRNNmCdv" +
            "EW\nLc5WuxmBhQKBgBENbtchgUBBbdWKz1hJbvt3irrOmDqT/B9r+kd0f+reciHm/4lM\nCouL5d9icQqIXCt/VZKHqMiHL78l8/gZYctMl" +
            "Fp5u+lJmMkL7SfxvxoNLfMYsDtQ\n3Ge5t/+fQ8FmvKr3vLVvshw4xjQYe9tH3FOxoQ6ekrq8DLKw1IZmRzNpAoGAGhrB\nY3vdDi0klK" +
            "WM/AzDTS+a2Nk9vb/BmHgCgL1XOjPqQPZguFbkjohU5d7znonUJN47\nPf7RWw2xMsVhpgV/8Idp9QX7zX4UnHrwl5H8CwlcjEpoEB8Rpvo" +
            "etoBWL84Glgmj\n0UqWhEBiQnY8BZkDyBytkhp06nkWzsAmw5/V0HkCgYAGXKw5B0VhGcJ933aHdvoS\nKZJb4F5EvzjrpFVwDeLIoR64Nt" +
            "KBEXRtAqrFu3CpiJH3I6snjxTg9sNVcqru4SpL\n/lLfH6/TWVc0VUZsWwJNxLgBScZYliw+DARhNvyf8rgGGgotb8/JcdE5NQyhOlpb\ngF" +
            "Wx38c5jfNe7ZlpB8eNdw==\n-----END PRIVATE KEY-----\n";

    private final static String RSA_SHA256 = "SHA256withRSA";

    private final static String KEY_TAG_PATTERN = "-----[A-Z ]+-----";

    private final static String RSA_ALGORITH = "RSA";

    private static String getBase64URLString(String str) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] keyStringToBytes(String keyString) {
        keyString = keyString
                .replaceAll(KEY_TAG_PATTERN, "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(keyString);
    }

    private static PrivateKey getPrivateKey(String privateKeyStr) throws Exception {
        byte[] privateKeyBytes = keyStringToBytes(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITH);

        PrivateKey privateKey = kf.generatePrivate(keySpec);

        return privateKey;
    }

    private static String sign(String content, String privateKeyString) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyString);

        Signature signer = Signature.getInstance(RSA_SHA256);
        signer.initSign(privateKey);
        signer.update(content.getBytes("UTF-8"));

        byte[] signatureBytes = signer.sign();

        String signature = Base64.getUrlEncoder().encodeToString(signatureBytes);

        return signature;

    }

    public static String signContent(String header, String claim) throws Exception {
        String jwtContent = getBase64URLString(header) + "." + getBase64URLString(claim);
        return jwtContent + "." + sign(jwtContent, PRIVATE_KEY);
    }
}
