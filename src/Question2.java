import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;


public class Question2 {
	// Sample string 
	private static String SAMPLE_TEXT = "The quick brown fox jumps over the lazy dog";
	private static SecretKey key;
	private static final SecureRandom secureRandom = new SecureRandom();
	
	private static final String password = "MichaelIsFool";
	private static String salt;
	private static int pswdIterations = 65536  ;
	private static int keySize = 256;
	private static byte[] ivBytes;
	
	/**
	 * Question 2: Part A,B,C,D:
	 * Here we are encrypting sample text with AES with randomly generated key
	 * @throws Exception 
	 */
	public static void main(String[] args) 
			throws Exception {
		// Message:
		System.out.println(SAMPLE_TEXT);
		
		// ----- Question 2: Part A w/ 256 encryption -----
		String check = "";
        String encryptedText = encrypt(SAMPLE_TEXT);
		System.out.println("----- Question 2: Part A w/ 256 -----");
		System.out.println("Encrypted string: " + encryptedText);           
        check = decrypt(encryptedText);
        System.out.println("Decrypted string: " + decrypt(encryptedText)); 
        checkCon(check, SAMPLE_TEXT);
		
		System.out.println("----- Question 2: Part A -----");
		// ----- Question 2: Part A -----
		// Run encrypt:
		System.out.println("Encrypting...");
		byte[] enc = encrypt();
		
		// Now run decryption
		System.out.println("Decrypting...");
		String output = decrypt(enc);
		// Print out decrypted text
		System.out.println(output);

		// Verify consistency
		checkCon(output, SAMPLE_TEXT);
		
		System.out.println("----- Question 2: Part B -----");
		
		// ----- Question 2: Part B -----
		// Print out digest for HMAC. 
		String testB = hmacDigest(SAMPLE_TEXT, "testKey", "HmacSHA256");
		System.out.println("Digest: " + testB); 
		System.out.println("----------");
		
		// Verify consistency
		checkCon(testB, hmacDigest(SAMPLE_TEXT, "testKey", "HmacSHA256"));
		// Check with different key: this should be false
		checkCon(testB, hmacDigest(SAMPLE_TEXT, "wrongKey", "HmacSHA256"));
		
		System.out.println("----- Question 2: Part C -----");
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// Run encrypt + tampering test:
		System.out.println("Testing encryption for tampering...");
		testAesGcm();
		
		// Check consistency
		System.out.println("----------");
		testCon();
		
		System.out.println("----- Question 2: Part D -----");
		System.out.println("Generating an RSA keypair...");
		// Generate Keypair
		KeyPairGenerator kG = KeyPairGenerator.getInstance("RSA");
		kG.initialize(2048);
		KeyPair pair = kG.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubA = fact.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec privA = fact.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
		
		// Show modulus and exponents
		// I know this isn't what should ever be done in practice but I want to show
		// the details of the keys to prove they were generated
		showDetails(pubA.getModulus(), pubA.getPublicExponent());
		showDetails(privA.getModulus(), privA.getPrivateExponent());
	}
	
	// ---------- 256 AES Code ---------- 

	public static String encrypt(String plainText) throws Exception {   

		//get salt
		salt = generateSalt();      
		byte[] saltBytes = salt.getBytes("UTF-8");

		// Derive the key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(
				password.toCharArray(), 
				saltBytes, 
				pswdIterations, 
				keySize
				);

		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		//encrypt the message
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		AlgorithmParameters params = cipher.getParameters();
		ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
		return new Base64().encodeAsString(encryptedTextBytes);
	}

	@SuppressWarnings("static-access")
	public static String decrypt(String encryptedText) throws Exception {

		byte[] saltBytes = salt.getBytes("UTF-8");
		byte[] encryptedTextBytes = new Base64().decodeBase64(encryptedText);

		// Derive the key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(
				password.toCharArray(), 
				saltBytes, 
				pswdIterations, 
				keySize
				);

		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		// Decrypt the message
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));


		byte[] decryptedTextBytes = null;
		try {
			decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return new String(decryptedTextBytes);
	}

	public static String generateSalt() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
		random.nextBytes(bytes);
		String s = new String(bytes);
		return s;
	}

	// ----------- END 256 AES ---------
	
	// ----- Question 2: Part A -----
	public static byte[] encrypt() 
			throws NoSuchAlgorithmException, NoSuchProviderException, 
			NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		
		// First randomly generate key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(new SecureRandom());
		//keyGen.init(128);
		key = keyGen.generateKey();
		
		// Setup the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");	
		cipher.init(Cipher.ENCRYPT_MODE,key);
		
		// Encrypt
		byte[] stringBytes = SAMPLE_TEXT.getBytes("UTF8");
		byte[] raw = cipher.doFinal(stringBytes);
		
		System.out.println("Encrypted string: " + raw);
		return raw;
	}
	
	// ----- Question 2: Part A -----
	public static String decrypt(byte[] raw) 
			throws NoSuchAlgorithmException, NoSuchProviderException, 
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
			BadPaddingException, UnsupportedEncodingException {
		
		// Get cipher object
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		cipher.init(Cipher.DECRYPT_MODE, key);
		
		// Decrypt
		byte[] op = cipher.doFinal(raw);
		String clear = new String(op, "UTF8");
		
		return clear;
	}
	
	// ----- Question 2: Part A -----
	public static Boolean checkCon(String a, String b){
		System.out.println("Checking consistency...");
		//System.out.println("Comparing \"" + a + "\" with \"" + b + "\"");
		boolean con = a.equals(b);
		if(!con) System.out.println("\"" + a + "\" NOT consistent with \"" + b + "\"");
		else System.out.println("\"" + a + "\" IS consistent with \"" + b + "\"");
		return a.equals(b);
	}

	// ----- Question 2: Part B -----
	public static String hmacDigest(String msg, String keyStr, String algo) {
		String digest = null;
		try {
			SecretKeySpec key = new SecretKeySpec((keyStr).getBytes("UTF-8"), algo);
			Mac mac = Mac.getInstance(algo);
			mac.init(key);
			
			byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));
			
			StringBuffer hash = new StringBuffer();
			for(int i = 0; i < bytes.length; i++){
				String hex = Integer.toHexString(0xFF & bytes[i]);
				if(hex.length() == 1) {
					hash.append('0');
				}
				hash.append(hex);
			}
			digest = hash.toString();
		} catch (UnsupportedEncodingException e) {			
		} catch (InvalidKeyException e) {
		} catch (NoSuchAlgorithmException e) {
		}
		return digest;
	}
	
	// ----- Question 2: Part C -----
	// Test encryption + showing tamper detection
	public static void testAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = SAMPLE_TEXT.getBytes("ASCII"); 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		cipher.init(false, new AEADParameters(new KeyParameter(randomKey), 128, randomIv));
		
		try {
			readFromStream(new org.bouncycastle.crypto.io.CipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  The BouncyCastle implementation of the CipherInputStream detects MAC verification errors and
			//  throws a InvalidCipherTextIOException if an error occurs. Nice! A more or less minor issue
			//  however is that it is incompatible with the standard JCE Cipher class from the javax.crypto 
			//  package. The new interface AEADBlockCipher must be used. The code below is not executed.		

			System.out.println("Test D: org.bouncycastle.crypto.io.CipherInputStream:        NOT OK, tampering not detected");						
		}
		catch (InvalidCipherTextIOException e) {
			System.out.println("Test D: org.bouncycastle.crypto.io.CipherInputStream:        OK, tampering detected");						
		}
	}

	// ----- Question 2: Part C -----
	// Check consistency
	public static void testCon() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = SAMPLE_TEXT.getBytes("ASCII"); 		
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);		
		
		// Decrypt with regular CipherInputStream (from JDK6/7)
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			byte[] decryptedPlaintext = readFromStream(new javax.crypto.CipherInputStream(new ByteArrayInputStream(originalCiphertext), cipher));
			String a = new String(originalPlaintext, "ASCII");
			String b = new String(decryptedPlaintext, "ASCII");
			checkCon(a,b);
		}
		catch (Exception e) {
			System.out.println("Caught exception: " + e);
		}
	}
	
	// ----- Question 2: Part C -----
	// Read from stream
	private static byte[] readFromStream(InputStream inputStream) throws IOException {
		ByteArrayOutputStream decryptedPlaintextOutputStream = new ByteArrayOutputStream(); 
		
		int read = -1;
		byte[] buffer = new byte[16];
		
		while (-1 != (read = inputStream.read(buffer))) {
			decryptedPlaintextOutputStream.write(buffer, 0, read);
		}
		
		inputStream.close();
		decryptedPlaintextOutputStream.close();
		
		return decryptedPlaintextOutputStream.toByteArray();  		
	}
	
	// ----- Question 2: Part C -----
	// Encrypt
	private static byte[] encryptWithAesGcm(byte[] plaintext, byte[] randomKeyBytes, byte[] randomIvBytes) throws IOException, InvalidKeyException,
	InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		SecretKey randomKey = new SecretKeySpec(randomKeyBytes, "AES");

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, randomKey, new IvParameterSpec(randomIvBytes));

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);

		cipherOutputStream.write(plaintext);
		cipherOutputStream.close();

		return byteArrayOutputStream.toByteArray();
	}
	
	
	// ----- Question 2: Part C -----
	// Helper function
	private static byte[] createRandomArray(int size) {
		byte[] randomByteArray = new byte[size];
		secureRandom.nextBytes(randomByteArray);

		return randomByteArray;
	}
	
	public static void showDetails(BigInteger mod, BigInteger exp){
		try {
			System.out.println("Mod: " + mod);
			System.out.println("Exponent: " + exp);
		} catch (Exception e) {
			System.err.println("Unexpected error " + e);
		}
	}
}
