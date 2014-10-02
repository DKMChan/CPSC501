/******************************************************************************
File: 	        decryptFile.java
				Computer Science 418 Assignment 1
Created:	    October 5, 2013        
Author:         Desmond Chan
Student ID:     10063158

Description:
This program was created using a lot of code from the demo.java file provided to us
 This program performs the following cryptographic operations on the input file:
    - computes a SHA-1 hash of the file's contents
    - decrypts the file using AES-128 and a randomly generated key using the user input seed, and writes it to 
      <output file>


Requires:       java.io.*, java.security.*, javax.crypto.*

Compilation:    javac decryptFile.java

Execution: java decryptFile <ciphertext file> <plaintext file> <seed>

Notes:
http://www.aci.net/kalliste/dsa_java.htm

******************************************************************************/


import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class decryptFile{
	private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;

	public static void main(String args[]) throws Exception{
		FileInputStream in_file = null;
		FileInputStream in_file2 = null;
		FileOutputStream out_file = null;
		byte[] sha_hash = null;
		byte[] checkdigest = null;
		byte[] aes_ciphertext = null;
		byte[] seed = null;
		byte[] decrypt = null;
		String decrypted_str = new String();
		int read_bytes = 0;
		String message;
		String seedkey;
		boolean verified = false;

		try{
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		out_file = new FileOutputStream(args[1]);
		seedkey = args[2];
		seed = seedkey.getBytes();

		
		//read file
		//I want to read the file then split it into message and digest parts
		
		in_file2 = new FileInputStream(args[0]);
		byte[] ciphtext = new byte[in_file2.available()];
		read_bytes = in_file2.read(ciphtext); 
		//System.out.println("Message Length " + read_bytes);
		
		//key setup - generate 128 bit key using input seed
		key_gen = KeyGenerator.getInstance("AES");
		secureRandom.setSeed(seed);
		key_gen.init(128,secureRandom);
		sec_key = key_gen.generateKey();
		//get key material in raw form
		raw = sec_key.getEncoded();
		sec_key_spec = new SecretKeySpec(raw, "AES");
		
		//decrypt
		//create the cipher object that uses AES as the algorithm
		sec_cipher = Cipher.getInstance("AES");	
		byte[] decryption = new byte[ciphtext.length];
		decryption = aes_decrypt(ciphtext);
		//System.out.println("decrypted length : " + decryption.length);
		
		//Used for getting the length of the message from the decrypted 
		
		//convert and store length of the message into 4 bytes
		byte[] mlength = new byte[4];
		mlength[0] = decryption[0];
		mlength[1] = decryption[1];
		mlength[2] = decryption[2];
		mlength[3] = decryption[3];
		
		int msize = convertToInt(mlength);
		System.out.println("Length of message : " + msize);
		
		//Two new arrays for containing the message and the digest
	
		byte[] dmessage = new byte[msize];
		byte[] prevDigest = new byte[decryption.length - 4 - msize];
		
		//Get message portion from the decrypted message
		for(int i = 0; i <= msize - 1; i++)
		{
		  dmessage[i] = decryption[i+4];
		}
		

		//Get digest portion from decrypted message
		//we know that the message length is contained in 4 bits and using an array we need to subract an additional 1
		//since arrays start at 0
		for(int i = 0; i <= decryption.length - 5 - msize;i++)
		{
		  prevDigest[i] = decryption[i + 4 + msize];
		}
		

	//	System.out.println("Previous Digest length :" + prevDigest.length);
		//SHA-1 Hash
		sha_hash = sha1_hash(dmessage);
		//System.out.println("Current Hash :" + sha_hash);
		
		//verify digest
		verified = verifyDigest(prevDigest,sha_hash);
		System.out.println("Message Modified? " + verified);
		decrypted_str = new String(dmessage);
		//System.out.println("Decrypted Message: " + decrypted_str);
		out_file.write(dmessage);
		out_file.close();
	

	

	
			
		}
		//exception thrown when user inputs wrong key
		catch(Exception e){
			System.out.println("Wrong Decryption Key");
		}
	
		
		
		finally{
			if (in_file != null){
				in_file.close();
			}
			if(out_file != null){
				out_file.close();
			}
			if(in_file2 != null){
				in_file2.close();
			}
		}
	}

	public static byte[] sha1_hash(byte[] input_data) throws Exception{
		byte[] hashval = null;
		try{
			//create message digest object
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			
			//make message digest
			hashval = sha1.digest(input_data);
		}
		catch(NoSuchAlgorithmException nsae){
			System.out.println(nsae);
		}
		return hashval;
	}



	public static byte[] aes_decrypt(byte[] data_in) throws Exception{
		byte[] decrypted = null;
		String dec_str = null;
		try{
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

			//do decryption
			decrypted = sec_cipher.doFinal(data_in);

			//convert to string
			//dec_str = new String(decrypted);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return decrypted;
	}



	//Compare both digests and returns true if they are unchanged otherwise it is false
	public static boolean verifyDigest(byte[] previousDigest, byte[] CurrentDigest)
	{
		boolean verified = false;
		int i = 0;
		while(i < CurrentDigest.length)
		{
			if(previousDigest[i] != CurrentDigest[i])
			{
			 i = CurrentDigest.length;
			 verified = true;
			}
			i = i + 1;
		}

		return verified;
	}


    /*
     * Converts a byte array to hex string
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        } 
        return buf.toString();
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
		
		}
	//used for converting a byte array into an integer
	//code taken from stackoverflow.com
	public static int convertToInt(byte[] a) 
	{
	    return   a[3] & 0xFF | (a[2] & 0xFF) << 8 | (a[1] & 0xFF) << 16 | (a[0] & 0xFF) << 24;
	}	
		

}
