/******************************************************************************
File: 	        secureFile.java
Purpose:        Java demo for cryptographic primitives
Created:	    October 5, 2013        
Author:         Desmond Chan
Student ID:     10063158

Description:
This program was created using a lot of code from the demo.java file provided to us
 This program performs the following cryptographic operations on the input file:
    - computes a SHA-1 hash of the file's contents
	- calculates length of the message and appends it to the message + digest
    - encrypts the file using AES-128 and a randomly generated key using a user input seed, and writes it to 
      <output file>


Requires:       java.io.*, java.security.*, javax.crypto.*

Compilation:    javac demo.java

Execution: java secureFile <plaintext file> <ciphertext file> <seed>

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
import java.lang.*;

public class secureFile{
	private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;

	//for DSA
	private static KeyPairGenerator keypairgen = null;
	private static KeyPair keypair = null;
	private static DSAPrivateKey private_key = null;
	private static DSAPublicKey public_key = null;
	private static Signature dsa_sig = null;
	private static SecureRandom secRan = null;
	private static BigInteger big_sig = null;

	public static void main(String args[]) throws Exception{
	    ByteArrayOutputStream output = new ByteArrayOutputStream();
		FileInputStream in_file = null;
		FileInputStream in_file2 = null;
		FileOutputStream out_file = null;
		byte[] sha_hash = null;
		byte[] hmac_hash = null;
		byte[] aes_ciphertext = null;
		byte[] sig = null;
		byte[] seed = null;
		String decrypted_str = new String();
		//byte[] msgdigest = null;
		int read_bytes = 0;
		
		String seedkey;
		boolean verify = false;

		try{
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			in_file = new FileInputStream(args[0]);
			out_file = new FileOutputStream(args[1]);
			seedkey = args[2];
			seed = seedkey.getBytes();
			

			//read file into a byte array
			byte[] msg = new byte[in_file.available()];
			read_bytes = in_file.read(msg);
			
			//Convert the read number of bytes(int) into a byte array so we can create a new array
			byte[] byteCount = convertToByte(read_bytes);
			
			//length of the message in bytes
			System.out.println("Message length " + read_bytes);
			

			//make the SHA-1 Hash
			sha_hash = sha1_hash(msg);
			//print out hash in hex
			//System.out.println("SHA-1 Hash: " + toHexString(sha_hash));
			
			
			//Append number of bytes to the beginning of the message to use as reference
			//System.arraycopy makes an array using the format(source,source position, destination, destination position, number of elements)
			byte[] messageCount = new byte[byteCount.length + msg.length];			//the new array has total size of #ofbytes + message
			System.arraycopy(byteCount,0,messageCount,0,byteCount.length);			//add the two arrays
			System.arraycopy(msg,0,messageCount,byteCount.length,msg.length);
			
			//Add the previous array with the message digest
			//make a new byte array of messagecount + message + digest
			byte[] msgdigest = new byte[messageCount.length + sha_hash.length];
			//first part of byte array = #ofbytes + message
			System.arraycopy(messageCount,0,msgdigest,0,messageCount.length);
			//second part of byte array = digest
			System.arraycopy(sha_hash,0,msgdigest,messageCount.length,sha_hash.length);
			
			//total size of the array
			//System.out.println("Combined :" +msgdigest.length);
			
			//encrypt file with AES
			//key setup - generate 128 bit key using the input seed
			key_gen = KeyGenerator.getInstance("AES");
			secureRandom.setSeed(seed);
			key_gen.init(128,secureRandom);
			sec_key = key_gen.generateKey();

			//get key material in raw form
			raw = sec_key.getEncoded();
			sec_key_spec = new SecretKeySpec(raw, "AES");

			//create the cipher object that uses AES as the algorithm
			sec_cipher = Cipher.getInstance("AES");	

			//do AES encryption on the byte array #ofbytes + message + message digest
			aes_ciphertext = aes_encrypt(msgdigest);
			//System.out.println("encrypted file: " + toHexString(aes_ciphertext));
			//Write encrypted message to file
			out_file.write(aes_ciphertext);
			out_file.close();
			
	
		    System.out.println("Final size " +aes_ciphertext.length);

		
			
		}
		catch(Exception e){
			System.out.println(e);
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

	

	public static byte[] aes_encrypt(byte[] data_in) throws Exception{
		byte[] out_bytes = null;
		try{
			//set cipher object to encrypt mode
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec);

			//create ciphertext
			out_bytes = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return out_bytes;
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
	
	//convert an integer into a byte array
	//code taken from stackoverflow.com
	public static byte[] convertToByte(int n) {
	byte[] a = new byte[4];
	for (int i = 0; i < 4; i++) {
		int j = (a.length - 1 - i) * 8;
		a[i] = (byte) ((n >>> j) & 0xFF);
	}	
	return a;
	}

}
