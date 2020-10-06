import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

public class Start {

    public static void main(String[] args) {
        if (checkArgs(args)) {
            System.out.println("Problem with arguments");
            return;
        }

        String key = toHex(generateStrongAESKey(256).getEncoded());

        try {
            int number = SecureRandom.getInstanceStrong().nextInt(args.length);
            String hmac = hmacDigest(number + "", key, "HmacSHA256");

            int variant = step(hmac, args);
            if (variant == 0) {
                return;
            }

            String result = getResult(args, variant, number);

            System.out.println("Your move: " + args[variant - 1]);
            System.out.println("Computer move: " + args[number]);
            System.out.println(result);
            System.out.println("HMAC key: " + key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String getResult(String[] args, int variant, int number) {
        switch (moreOrLess(args.length, variant - 1, number)) {
            case -1:
                return "Loose";
            case 0:
                return "Draw";
            case 1:
                return "Win";
        }
        return "Some problems";
    }

    public static int step(String hmac, String[] args) {
        printMenu(hmac, args);
        int variant = getVariant();
        if (variant == -1 || variant > args.length) {
            return step(hmac, args);
        }
        return variant;
    }

    public static void printMenu(String hmac, String[] args) {
        System.out.println("HMAC=" + hmac);
        for (int i = 0; i < args.length; i++) {
            System.out.println(i + 1 + " - " + args[i]);
        }
        System.out.println("0 - Exit");
    }

    public static int getVariant() {
        System.out.print("Enter your move: ");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        int variant = -1;
        try {
            variant = Integer.parseInt(reader.readLine());
        } catch (IOException | NumberFormatException ignored) {

        }
        return variant;
    }

    public static boolean checkArgs(String[] args) {
        return args.length < 3 ||
                new HashSet<>(Arrays.asList(args)).size() != args.length ||
                args.length % 2 != 1;
    }

    public static int moreOrLess(int length, int choice, int moreThen) {
        if (choice == moreThen) {
            return 0;
        }
        int middle = (length - 1) / 2;
        if (choice > moreThen || choice + middle <= moreThen) {
            return 1;
        }
        return -1;
    }

    public static SecretKey generateStrongAESKey(final int keysize) {
        final KeyGenerator kgen;
        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("AES key generator should always be available in a Java runtime", e);
        }
        final SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("No strong secure random available to generate strong AES key", e);
        }
        kgen.init(keysize, rng);

        return kgen.generateKey();
    }

    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static String hmacDigest(String msg, String keyString, String algo) {
        String digest = null;
        try {
            SecretKeySpec key = new SecretKeySpec((keyString).getBytes(StandardCharsets.UTF_8), algo);
            Mac mac = Mac.getInstance(algo);
            mac.init(key);

            byte[] bytes = mac.doFinal(msg.getBytes(StandardCharsets.US_ASCII));

            StringBuilder hash = new StringBuilder();

            for (byte aByte : bytes) {
                String hex = Integer.toHexString(0xFF & aByte);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }
            digest = hash.toString();
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No such algorithm");
            e.printStackTrace();
        }
        return digest;
    }
}
