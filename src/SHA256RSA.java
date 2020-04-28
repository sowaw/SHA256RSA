import org.json.simple.JSONObject;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class SHA256RSA {
/*
    public static void main(String[] args) throws UnsupportedEncodingException {
        //Base64 decoder = new Base64();
        String url = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        byte[] decoded = Base64.getUrlDecoder().decode(url);

        System.out.println(new String(decoded, "UTF-8") + "\n");
    }
*/

    public static void main(String[] args) throws Exception {


        JSONObject obj = new JSONObject();
        obj.put("alg", "RS256");
        obj.put("typ", "JWT");

        String input = obj.toString();

        System.out.println(obj.toString());

        String strPK = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgE" +
                "AAoIBAQCV3FkZ+aqOyk71\ngG1thMIM6t6mt2PfUQAwMuByZ7rK+G+Rs8V/LwscTTVtzuDpovd40m3CfqT" +
                "uWJvU\nXpicBzwmm4mYyTCXntoRVYhyq/F960CvF6UMAVE5xYUVl1BP3U2k2YiUTSNjA/FX\nCBcpdQ61" +
                "QlB1k1KnB8obsQ2RCkVG+XzKhUgYWq93qMzZhoE1FD3a/NtaG4UwR5Lt\nj2KK8jNIAVckCiN6JjZKPtkVTHd" +
                "HHKf1OZ+FRgKZdMKuK63YzNtfoNg6v2QxRZjj\n2FOt+qA341E9fZTDQkkaOwIdh7UWfJDgNhWHAcIv4qFpx4TI" +
                "no7xYzB3khGq3eCY\nhcZaYisXAgMBAAECggEAL+QAZ3AlZMdbL1Jw5ehgmP8v0whVNsbsb/q6RmVGyNlW\n0jGogi" +
                "n2+37i/an4r0FAo5BfuiF9tJuFhPsL+wTG4LGg6b4VtMZzesmiNr8jB/H3\ntFyyhmEfY35vNsSpyjP3PaC06Gu0TM60" +
                "P/Nab4m0fxFnpANGDRHMsUfGBZ1KIVFZ\nLb0HndfDLbBBkgmmFsQ0AagYPXLrcMcn/qmW2uCsYQ233LceWZHwDVTKNqDI" +
                "ul1y\nZJRuZFRBaIps9GcqGZYcfY74IcPYnCucTqnHWpV/wwmXwTijm/NUN9wPu0M2Yr9U\nK7x+Q0KFQ/5GC3vDJTGgRF" +
                "gOhb/hgoFuM8e/gDDKIQKBgQDHhZWDvMvb9gpjttiV\nLwZ3ik6LPnvUquj2NvIukEwBZgQQ+0Z/Tjn+aTIGMH" +
                "JAG90vji3/4J6UYzOnQucf\nu9c671nyCyg5n6OVoKe4414pcfTCktQQXX8TTiXHY7S1bIGfug2Y+0WMlJhnjf" +
                "86\no2AuQwGBE7/Ng12UewySiOXboQKBgQDASA6e3TG7mRg1DFH2zLEt6n4LS8N3+rmT\nOV9aROlx1SdUXqUhi" +
                "DYy3T6UFdAoTbKFArZK63ySj4Ln0GcGZOEQ6nfhyFosWOCJ\nF7wY81EYueZVYMXzZyNvvvB8H34i3JUUYED4TFX" +
                "TggFkg9G+KgBYNfP7aM21uRN2\nzXpu/HpLtwKBgQC6kuwxeIaZdgZZIE5/kq3VcvvnsdJSGFAojVECweSRGjiL" +
                "OK2/\ntgL9KJmiuALeeC/pnGbfc8hWsj1HF4TRY/HsJo5RjKVc3S83aDfu6I7Q6sMaf/rW\nItgF0Xn6bf45+PF" +
                "tz6mPeMicoQezLlGRH9185SOu9CzTnRgRFM+451MqgQKBgGLe\nKjZhggr2A05zkUmXopr7cegZAt8UWotq+q6Nt" +
                "INFmL13FO2S/ltVC7JVLP0sRljC\nNj17rEgn5qWPsQnGoTtzdETyIfufj4SuYZdqtQ5DuD26Ts6C/+ObiEgqYU9HoJ" +
                "gj\njgSeK5tfw5uNdDGVoyu4QkXJc8y251009nlO9QstAoGATEf4x6xWDCZbLdWvVuJF\nq5YIU4o6I9iphmG1L1FCKK" +
                "BaZErKwiojQiXE+14wFYNl5RAKdyDk81j/MgKMnE8T\nV5E3/Ikt31p9wBIep4NsTuoBK436x9K73j/t5MHj1Mbld5n" +
                "YTg6MXSY8lX0lplMX\n6lNNgRMkIqtlF47b1+Ss/kE=\n-----END PRIVATE KEY-----\n";

        String base64Signature = signSHA256RSA(input, strPK);

        System.out.println("Signature = " + base64Signature);

        System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(obj.toString().getBytes(StandardCharsets.UTF_8)));

        Date date = new Date();

        System.out.println(date.getTime()/1000 + 3600);
        System.out.println(date.getTime()/1000);

        JSONObject claim = new JSONObject();
        claim.put("iss", "roche-3rs@rs-project-274507.iam.gserviceaccount.com");
        claim.put("scope", "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file" +
                "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/spreadsheets" +
                "https://www.googleapis.com/auth/spreadsheets.readonly");
        claim.put("aud", "https://oauth2.googleapis.com/token");
        claim.put("exp", date.getTime()/1000 + 3600);
        claim.put("iat", date.getTime()/1000);

        System.out.println(claim.toString());
        System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(claim.toString().getBytes(StandardCharsets.UTF_8)));

    }

    private static String signSHA256RSA(String input, String strPK) throws Exception {
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

        return Base64.getUrlEncoder().encodeToString(s);

    }
}
