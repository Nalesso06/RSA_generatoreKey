import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import java.util.StringTokenizer;

public class RSA {
    
    private static final String TestoDaInviare = "PrimaProva";
    private static final String Delimitatore = ";";

    public static void main(String[] args) {
        executeRSA();
    }

    private static void executeRSA() { 
        Random randomGenerator = new Random();

        // Step 1: Generate distinct prime numbers
        BigInteger prime1 = generatePrime(randomGenerator);
        BigInteger prime2 = generatePrime(randomGenerator);
        
        while (prime1.equals(prime2) || prime1.multiply(prime2).compareTo(BigInteger.valueOf(30000)) <= 0) {
            prime1 = generatePrime(randomGenerator);
            prime2 = generatePrime(randomGenerator);
        }

        BigInteger n = prime1.multiply(prime2);
        BigInteger V = prime1.subtract(BigInteger.ONE).multiply(prime2.subtract(BigInteger.ONE));
        BigInteger publicKey = generateCoprime(V);

        BigInteger privateKey = calculatePrivateKey(publicKey, V);

        System.out.println("Numero Primo 1: " + prime1);
        System.out.println("Numero Primo 2: " + prime2);
        System.out.println("Modulo (n): " + n);
        System.out.println("V: " + V);
        System.out.println("Chiave pubblica (e): " + publicKey);
        System.out.println("Chiave privata (d): " + privateKey);

        String encryptedData = encryptData(TestoDaInviare, publicKey, n);
        System.out.println("Encrypted Data: " + encryptedData);

        decryptData(encryptedData, privateKey, n);
    }

    private static BigInteger generatePrime(Random randomGenerator) {
        return BigInteger.probablePrime(Long.BYTES * 8, randomGenerator);
    }

    private static BigInteger generateCoprime(BigInteger V) {
        Random random = new Random();
        BigInteger coprime;
        do {
            coprime = BigInteger.probablePrime(Long.BYTES * 8, random);
        } while (!coprime.gcd(V).equals(BigInteger.ONE) || coprime.compareTo(V) >= 0);
        return coprime;
    }

    private static BigInteger calculatePrivateKey(BigInteger publicKey, BigInteger V) {
        return publicKey.modInverse(V);
    }

    private static String encryptData(String plaintext, BigInteger publicKey, BigInteger n) {
        ArrayList<BigInteger> encryptedList = new ArrayList<>();
        StringBuilder encryptedString = new StringBuilder();

        for (char character : plaintext.toCharArray()) {
            BigInteger encryptedChar = BigInteger.valueOf((int) character).modPow(publicKey, n);
            encryptedList.add(encryptedChar);
            encryptedString.append(encryptedChar).append(Delimitatore);
        }

        System.out.println("Encryption steps: " + encryptedList);
        return encryptedString.toString();
    }

    private static void decryptData(String encryptedData, BigInteger privateKey, BigInteger n) {
        StringTokenizer tokenizer = new StringTokenizer(encryptedData, Delimitatore);
        ArrayList<BigInteger> decryptedList = new ArrayList<>();
        StringBuilder decryptedString = new StringBuilder();
        while (tokenizer.hasMoreTokens()) {
            BigInteger encryptedValue = new BigInteger(tokenizer.nextToken());
            BigInteger decryptedChar = encryptedValue.modPow(privateKey, n);
            decryptedList.add(decryptedChar);
            decryptedString.append((char) decryptedChar.intValueExact());
        }
        System.out.println("Numero decriptato: " + decryptedList);
        System.out.println("Testo decriptato: " + decryptedString);
    }
}
