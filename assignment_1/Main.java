/*
	Adam O'Flynn 12378651
	Cryptography and Security Protocols CA4005

	All work is solely my own unless otherwise stated.

*/

import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

class Main {
	public static void main(String[] args) throws Exception {
		// Used for testing and debugging, reads in required info
		if(args.length == 3){
			byte[] iv = DatatypeConverter.parseHexBinary(args[0]);
			byte[] salt = DatatypeConverter.parseHexBinary(args[1]);
			String password = args[2];
			Encryption e = new Encryption(iv, salt, password);
		}

		else{
			Encryption e = new Encryption();
		}
	}
}

class Encryption {
	private Cipher c;
	private byte[] iv, salt, cipher_text, aes;
	private String password;
	private SecretKey k;
	private IvParameterSpec r;

	// Files for input and output
	private File inputFile =  new File("code.zip");
	private File encryptedFile =  new File("encrypted.zip");
	private File decryptedFile = new File("decrypted.zip");
	private File keys = new File("keys.txt");

	/* This constructor allows you pass salt, iv and password as arguments on command line */
	public Encryption(byte[] iv, byte[] salt, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
	BadPaddingException
	{
		c = Cipher.getInstance("AES/CBC/NoPadding");

		aes = hashPassword(password, salt);
		k = getKey(aes);
		r = new IvParameterSpec(iv);
		
		/* Encrypt Method - 
		   @return cipher_text 
		*/
		
		c.init(Cipher.ENCRYPT_MODE, k, r);
		cipher_text = encrypt();
		System.out.println("File successfully encrypted. See file 'encrypted'.");
		
		/*	Decrypt Method 
			@return plaintext
		*/		
		c.init(Cipher.DECRYPT_MODE, k, r);
		byte[] plain_text = decrypt();
		System.out.println("File successfully decrypted. See file 'decrypted'.");
	 	
	 	// Get RSA encryption of password
		encryptPassword(password);
		System.out.println("Password successfully encrypted. See file 'keys'.");

		//Output this tests keys to file.
		try{
			PrintWriter pw = new PrintWriter(new FileWriter(keys));
			pw.println("Initialisation Vector = " + DatatypeConverter.printHexBinary(iv));
			pw.println("Salt = " + DatatypeConverter.printHexBinary(salt));
			pw.println("AES Key = " + DatatypeConverter.printHexBinary(aes));
			pw.println("Password = " + password);
			pw.println("Encrypted Password using RSA = " + encryptPassword(password));

			pw.close();
		}catch (IOException e) {
			e.printStackTrace();
		}
	}

	/* This no args constructor is used to create a new IV, Salt and do encryption and decryption. */
	public Encryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
	BadPaddingException
	{
		c = Cipher.getInstance("AES/CBC/NoPadding");
		iv = getSalt();
		salt = getSalt();
		password = "@99fza3_";

		aes = hashPassword(password, salt);
		k = getKey(aes);
		r = new IvParameterSpec(iv);
		
		/* 
			 	Encrypt Method
		  	@return cipher_text 
		*/
		c.init(Cipher.ENCRYPT_MODE, k, r);
		cipher_text = encrypt();
		System.out.println("File successfully encrypted. See file 'encrypted'.");

		/*	
				Decrypt Method 
			  @return plaintext
		*/		
		c.init(Cipher.DECRYPT_MODE, k, r);
		byte[] plain_text = decrypt();
		System.out.println("File successfully decrypted. See file 'decrypted'.");
	 	
		encryptPassword(password);
		System.out.println("Password successfully encrypted. See file 'keys'.");

		try{
			PrintWriter pw = new PrintWriter(new FileWriter(keys));
			pw.println("Initialisation Vector = " + DatatypeConverter.printHexBinary(iv));
			pw.println("Salt = " + DatatypeConverter.printHexBinary(salt));
			pw.println("AES Key = " + DatatypeConverter.printHexBinary(aes));
			pw.println("Encrypted Password using RSA = " + encryptPassword(password));

			pw.close();
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/*
		Encryption method to encrypt message. We add padding according to the padding strategy described below in method padMessage().
	*/

	private byte[] encrypt() throws UnsupportedEncodingException, IllegalBlockSizeException, 
	BadPaddingException
	{
		try{
			if(!encryptedFile.exists()){
				encryptedFile.createNewFile();
				System.out.println("No encrypted file exists yet. Creating...");
			}
			FileInputStream inputStr = new FileInputStream(inputFile);

		  // Type cast as file.length() returns a long var
		  byte[] m = new byte[(int)inputFile.length()];
			byte[] cipher_text;

			// Read into byte array 'm' the file stream inputStr i.e inputFile
			inputStr.read(m);

			// Pad message 
			byte[] message = padMessage(m, c.getBlockSize());
		
			// Encrypt the padded message
			cipher_text = c.doFinal(message);

			// Write the ciphertext to a file.
			FileOutputStream outputStr = new FileOutputStream(encryptedFile);
			outputStr.write(cipher_text);

			outputStr.flush();
			outputStr.close();
			return cipher_text;
		}catch (IOException e) {
			System.out.println("There is no input file to encrypt... Try again please.");
			System.exit(0);
		}
		return cipher_text;
	}

	/*
		Decryption method on cipher text. After decryption, we remove extra padding and display plaintext.
	*/

	private byte[] decrypt() throws UnsupportedEncodingException, IllegalBlockSizeException, 
	BadPaddingException
	{
		try{
			if(!encryptedFile.exists()){
				encryptedFile.createNewFile();
				System.out.println("No encrypted file exists to decrypt.");
			}

			FileInputStream encFile = new FileInputStream(encryptedFile);
			FileOutputStream decFile = new FileOutputStream(decryptedFile); 

			// Read in the encrypted file
		  byte[] message = new byte[(int)encryptedFile.length()];
			encFile.read(message);
			
			// Decrypt the message including padding.
			byte[] plain = c.doFinal(message);

			// Remove the padding from the decrypted message and write to a file
			byte[] decVal = removePadding(plain, c.getBlockSize());
			decFile.write(decVal);

			encFile.close();
			decFile.flush();
			decFile.close();
			return decVal;
		}catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	} 

	/*
		Pad message if it is less than a multiple of 16 ( the blocksize of 128 bits)
		If it is not equal, append a 1000000 to the block and fill the rest of the block with zeros
		If it is equal to the blocksize, append a new block of 1000000 to the message and fill rest of block with zeros.	
	*/

	private static byte[] padMessage(byte[] m, int blockSize){
		int add = m.length % blockSize;
		int padAmount = blockSize - add;

		// Make a new array to hold message + padding
		byte[] arrayToPad = new byte[m.length + padAmount];
		System.arraycopy(m, 0, arrayToPad, 0, m.length);
		
		//0x80 is 10000000 in binary
		arrayToPad[m.length] = (byte)0x80; 

		// 
		for (int i = 1; i < padAmount; i++) {
				arrayToPad[m.length + i] = 0; 			
		}
		
		return arrayToPad;
	}

	/*
		When you decrypt the message, it is necessary to remove the padding that was placed on the message before being encrypted.
		This is done by finding the 1000000 block which we inserted. Once found, keep the index and copy the old array to 
		a new one until the index k i.e the end of the original array before encryption.
	*/

	private static byte[] removePadding(byte[] m, int blockSize){
		int size = m.length;
		int k;
		for (k = size - 1; k > 0 ; k--) {
			if( m[k] == (byte)0x80 ){
				/* Break because we have found the padded 10000000 we added. */
				break;
			}
		}
	  byte[] arrayNoPad = new byte[k];
	  System.arraycopy(m, 0, arrayNoPad, 0, k);
		return arrayNoPad;
	}

	private static String encryptPassword(String password) throws UnsupportedEncodingException{
		// Password into a BigInteger 
		BigInteger p = new BigInteger(password.getBytes("UTF-8"));
		BigInteger e = new BigInteger("65537");
		String hexString   = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190"
							 					 + "ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d"
												 + "3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c8652"
							 					 + "01fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
		
		BigInteger modulus = new BigInteger(hexString, 16);

		/*
			Right to Left Variant from notes.
			e = encryption exponent      
			N = public Modulus 
			p = password
			where y = p^e (mod N)

			Pseudocode from Notes

			y = 1
			for i = 0 to n - 1 do 
				if(e.i = 1) then y = (y*e) mod N
				e = (e*e) mod N
			end	

			I used Wikipedia's article on Modular Exponentiation and the notes for Number Theory 1 to make this function 
		*/	
		
		BigInteger y = BigInteger.ONE;
		while(e.compareTo(BigInteger.ZERO) > 0) {
			// Check for oddness in exponent where 0 is the index of the bit to check
			// Since odd, result is multiplied by base (password) 
			if(e.testBit(0)) y = (y.multiply(p)).mod(modulus);
			// Iterate through binary digits
			e = e.shiftRight(1);
			// Base (password) is squared
			p = (p.multiply(p)).mod(modulus);
		}

		return y.mod(modulus).toString(16);
	}

	// Generate a random 128 bit (16 byte) salt and iv.
	private static byte[] getSalt() {
		SecureRandom random = new SecureRandom();
		byte[] s = new byte[16];
		random.nextBytes(s);
		return s;
	}
	
	// Convert byte array into a SecretKey for cipher parameters
	private static SecretKey getKey(byte[] k) throws UnsupportedEncodingException
	{
		return new SecretKeySpec(k, 0, k.length, "AES");
	}

	public static byte[] hashPassword(String pass, byte[] salt) throws UnsupportedEncodingException{
		// Get Password into byte array to concatenate  with salt
		byte[] p = pass.getBytes("UTF-8");
		byte[] key = new byte[p.length + salt.length];

		// Copy password and salt arrays into each other to concatenate them. 
		System.arraycopy(p, 0, key, 0, p.length);
		System.arraycopy(salt, 0, key, p.length, salt.length);

		// Hash concatenation of password and salt 200 times
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			for (int i = 0; i < 200; i++) {
				key = digest.digest(key);
			}
		}catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}
}