/*
	Adam O'Flynn 12378651
	Cryptography and Security Protocols CA4005
	Assignment 2

	All work is solely my own unless otherwise stated.

*/

import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.io.*;

class Main {
	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException{
		ElGamal e = new ElGamal();
		e.generateKRS();
		e.output();
		e.checkDigitalSignature();
	}
}

class ElGamal {
	private String hexPrime = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd" +
														"ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc" +
														"8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
														"47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";

	private String hexGenerator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
														  	"e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
																"1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
																"64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";	

	// Convert hex string into BigInteger from base 16 (hexa)
	private BigInteger prime = new BigInteger(hexPrime, 16);								
	private BigInteger gen = new BigInteger(hexGenerator, 16);			
	// Create a BigInteger that is prime - 1.	
	private BigInteger prime_1 = prime.subtract(BigInteger.ONE);

	// Read in file i.e. message before hashing
	private byte[] zip = fileToSign("file.zip");

	// Generate the relevant numbers
	private BigInteger privateKey = generatePrivateKey();
	private BigInteger publicKey = generatePublicKey();
	private BigInteger message = hashMessage();
	private BigInteger k;
	private BigInteger r;
	private BigInteger s;

	// Create a new file keys that will hold the generated output 
	private File keys = new File("keys.txt");

	// x = 1 < x < p-1
	private BigInteger generatePrivateKey(){
		// Generate a random object r
		Random r = new Random();
		// Use the constructor from BigInteger to create a randomly generated BigInteger between 0 and 2^n - 1
		// Where n is the number of bits in prime. Use a while to loop until it is less than the original prime.
		// i.e. compareTo returns -1 signifying it is less than prime
		BigInteger randomInt = new BigInteger(prime.bitLength(), r);
		while (randomInt.compareTo(prime) == 1) {
			randomInt = new BigInteger(prime.bitLength(), r);
		}
		return randomInt;					
	}

	// y = g^x (mod prime)
	private BigInteger generatePublicKey(){	
		return gen.modPow(privateKey, prime);					
	}

	private BigInteger generateK(){
	  // Boolean value for checking if gcd returns 1
		Boolean equals1 = false;
		Random r = new Random();
		do {
			//Generate a new biginteger that is 1024 bits long and has a prime cardinality of 1, i.e. more chance of it being prime
			k = new BigInteger(prime.bitLength(), 1, r);
			//Check if the gcd of the new K and prime-1 is one
			equals1 = gcd(prime_1, k).equals(BigInteger.ONE);

		} while(equals1 == false && k.compareTo(prime_1) == 1); // If gcd != 1 and k isn't smaller than prime, do loop again..

		return k;					
	}

	// Generate r = g^k mod(prime)
	private BigInteger generateR(){
		return gen.modPow(k, prime);
	}

	// Generate S where S = (H(m)-xr)k^-1 (mod prime-1) where H is the hash function SHA-256.
	private BigInteger generateS(){
		// Get xr where x is private key
		BigInteger xMulR = privateKey.multiply(r);
		// Get hashed message minus above value.
		BigInteger concatEucl = message.subtract(xMulR);
		// Get (h(m)-xr) and k's inverse
		BigInteger s = concatEucl.multiply(multInverse());
		return s.mod(prime_1);
	}

	// This is a method to check if k and prime_1 are coprime i.e. gcd == 1
	private BigInteger gcd(BigInteger a, BigInteger b){
		// Base case for recursion, 
		if(b.equals(BigInteger.ZERO)) return a;
		return gcd(b, a.mod(b));
	}

	// Use SHA-256 to hash message (message is a file in this case.)
	private BigInteger hashMessage(){
		try{
			// Get instance of digest
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			// Digest the message once into a byte array and convert it back as an biginteger to be returned
			byte[] m = md.digest(zip);
			return new BigInteger(m);
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/* My implementation of the Extended Euclidean algorithm for use with the modular multiplicative inverse 

		 I used Wikipedia's articles on Modular Multipicative Inverse and the Extended Euclidean Algorithm
		 https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
		 https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
	*/ 
	private BigInteger[] extendedEucl(BigInteger a, BigInteger b){
		// Create an array to hold the values of d, x and y  - where d is the greatest common divisor 
		BigInteger[] ints = new BigInteger[3];
		// Base case
		if(b.equals(BigInteger.ZERO)){
			ints[0] = a;
			ints[1] = BigInteger.ONE;
			ints[2] = BigInteger.ZERO;
			return ints;
		}

		ints = extendedEucl(b, a.mod(b));
		BigInteger x = ints[1];
		BigInteger y = ints[2];
		ints[1] = y;
		ints[2] = x.subtract((a.divide(b)).multiply(y));
		return ints;
	}

	// Get multiplicative inverse of k using XGCD.
	private BigInteger multInverse(){
		return extendedEucl(k, prime_1)[1].mod(prime_1);
	}

	private byte[] fileToSign(String fis) {
		try{
			// Read in file and create a new input stream
			File f = new File(fis);
			FileInputStream inputFile = new FileInputStream(f);
			// Create a new byte array with the length of the message
			byte[] message = new byte[(int)f.length()];
			// Read file til EOF
			inputFile.read(message);
			inputFile.close();
			return message;
		} catch (FileNotFoundException e) {
			System.out.println("File specified does not exist.");
			System.exit(1);
		} catch(IOException e){
			e.printStackTrace();
		} 
		return null;
	}

	public void generateKRS(){
		// generate keys K, R, S and if S is 0, do it again.
		do {
			k = generateK();
			r = generateR();
			s = generateS();
		} while(s.equals(BigInteger.ZERO));
	}

	// Method to check that the signature is correct
	public void checkDigitalSignature(){
		// check that 0 < r < p and 0 < s < p-1
		Boolean rCheck = (r.compareTo(BigInteger.ZERO) == 1 && r.compareTo(prime) == -1);
		Boolean sCheck = (s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(prime_1) == -1);
		System.out.println("0 < R < Prime: " + rCheck + "\n0 < S < Prime - 1: " + sCheck);

		BigInteger left = gen.modPow(message, prime);
		// Split the Y^R and R^S calculations as you can't use pow() for a BigInteger exponent.
		BigInteger right = (publicKey.modPow(r, prime)).multiply(r.modPow(s,prime)).mod(prime);
		System.out.println("Verifying that  g^H(m) (mod p) = y^r r^s (mod p) is true: " + left.equals(right));
	}

	// Method to output the required values to a file keys.txt
	public void output(){
		try{
			PrintWriter pw = new PrintWriter(new FileWriter(keys));
			pw.println("Private Key = " + privateKey);
			pw.println();
			pw.println("Private Key Hexadecimal = " + privateKey.toString(16));
			pw.println();
			pw.println("Public Key = " + publicKey);
			pw.println();
			pw.println("Public Key Hexadecimal = " + publicKey.toString(16));
			pw.println();
			pw.println("K = " + k);
			pw.println();
			pw.println("R = " + r);
			pw.println();
			pw.println("R Hexadecimal = " + r.toString(16));
			pw.println();
			pw.println("S = " + s);
			pw.println();
			pw.println("S Hexadecimal = " + s.toString(16));
			pw.close();
			System.out.println("Please see file 'keys.txt' for the output of this digital signature");
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
}