package com.example;
 
public class Test {
     
	private static String SAMPLE_TEXT = "The quick brown fox jumps over the lazy dog";
    public static void main(String[] args) throws Exception {
        // TODO Auto-generated method stub
 
        AESDemo d = new AESDemo();
             
        System.out.println("Encrypted string: " + d.encrypt(SAMPLE_TEXT));           
        String encryptedText = d.encrypt(SAMPLE_TEXT);
        System.out.println("Decrypted string: " + d.decrypt(encryptedText));         
 
    }
}