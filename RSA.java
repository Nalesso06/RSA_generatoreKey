import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Scanner;

public class RSA {
    private static final String Delimitatore = ";"; 

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Inserisci la parola da inviare:");
        String TestoDaInviare = scanner.nextLine(); 
        System.out.println("La parola che hai inserito è: " + TestoDaInviare);
        
        executeRSA(TestoDaInviare); 
        scanner.close();
    }      

    private static void executeRSA(String TestoDaInviare) { 
        Random randomGenerator = new Random();

        // Genera due numeri primi distinti
        BigInteger prime1 = generatePrime(randomGenerator);
        BigInteger prime2 = generatePrime(randomGenerator);
        
        // Assicura che i numeri primi siano distinti e che il prodotto sia maggiore di 30000
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
        System.out.println("Funzione Totiente (φ): " + V);
        System.out.println("Chiave pubblica (e): " + publicKey);
        System.out.println("Chiave privata (d): " + privateKey);
        
        // Cifratura del messaggio
        String encryptedData = encryptData(TestoDaInviare, publicKey, n);
        System.out.println("Encrypted Data: " + encryptedData);
        
        // Decifratura del messaggio
        decryptData(encryptedData, privateKey, n);
    } 

    // Metodo per generare un numero primo casuale
    private static BigInteger generatePrime(Random randomGenerator) {
        return BigInteger.probablePrime(Long.BYTES * 8, randomGenerator);
    }

    // Metodo per generare un coprimo rispetto a V
    private static BigInteger generateCoprime(BigInteger V) {
        Random random = new Random();
        BigInteger coprime;
        do {
            coprime = BigInteger.probablePrime(Long.BYTES * 8, random); 
        } while (!coprime.gcd(V).equals(BigInteger.ONE) || coprime.compareTo(V) >= 0); 
        return coprime;
    }

    // Metodo per calcolare la chiave privata (d) come inverso modulo di e rispetto a φ
    private static BigInteger calculatePrivateKey(BigInteger publicKey, BigInteger V) {
        return publicKey.modInverse(V); // Calcola l'inverso moltiplicativo
    }

    // Metodo per cifrare il messaggio
    private static String encryptData(String plaintext, BigInteger publicKey, BigInteger n) {
        ArrayList<BigInteger> encryptedList = new ArrayList<>();
        StringBuilder encryptedString = new StringBuilder();

        // Cifra ogni carattere del testo in chiaro
        for (char character : plaintext.toCharArray()) { 
            BigInteger encryptedChar = BigInteger.valueOf((int) character).modPow(publicKey, n);
            encryptedList.add(encryptedChar);
            encryptedString.append(encryptedChar).append(Delimitatore); 
        }

        System.out.println("Crittografato: " + encryptedList);
        return encryptedString.toString();
    }

    // Metodo per decifrare il messaggio
    private static void decryptData(String encryptedData, BigInteger privateKey, BigInteger n) {
        StringTokenizer tokenizer = new StringTokenizer(encryptedData, Delimitatore);
        ArrayList<BigInteger> decryptedList = new ArrayList<>();
        StringBuilder decryptedString = new StringBuilder();

        // Decifra ogni valore crittografato
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
