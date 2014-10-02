Desmond Chan
Student ID : 10079569
CPSC 418 Assignment 1 


List of Files
- secureFile.java : This file will take as command line input <plaintext> <ciphertext> <seed>
		    plaintext: is the message to be read & encrypted
		    ciphertext: this the encrypted text
		    seed: this is the value used to generate the key

2. decryptFile.java : This file will take as command line input <ciphertext> <plaintext> <seed>
 		    ciphertext: this is the message to be decrypted
	            plaintext: this is the file to save the decrypted text to
		    seed: must be the same as the one used to encrypt it or we will get an error


PRNG:
SecureRandom 

Verification:
a new byte array is created where the first byte of the cipher text is the length of the message, this will then be added to
to message and message digest.
This will give us a byte array of size [number of bytes in message + message + message digest ], which is the ciphertext to be 
decrypted.
Using the number of bytes of the message we can check to see where to split the file
by doing this we can split the digest from the rest of the message and then compare the current digest with the previous one, 
and if they are different then the file has been modified and the message modified boolean(verified) will be set to true




Digest Seperation:
- First decrypt the ciphertext
- Then read the first byte of the ciphertext to get the size of the message to be decrypted
- Read all entries between the first byte and and msize.
- Store these in a seperate variable
- Read everything else between bytes size and length of the ciphertext
- Finally store these entries into a seperate variable for the digest.



How to compile:
javac secureFile.java
javac decryptFie.java

Bugs:
No known bugs