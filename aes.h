/**************************************************************
  File:          aes.h
  Description:   A program to implement the AES-128 encryption. 
  Author:        James Amo (Group 6)
  Organization:  IUSB, Computer and Information Sciences
  Date:          September 2018
***************************************************************/

#ifndef AES_128_H
#define AES_128_H

#define AES_BLOCK_SIZE      16
#define AES_ROUNDS          10  // 12, 14
#define AES_ROUND_KEY_SIZE  176 // AES-128 has 10 rounds, and there is a AddRoundKey before first round. (10+1)x16=176.


/*
* used in the implementation of the key expansion
*/
void KeyExpansionCore(unsigned char *in, unsigned char i);
/*
* round keys are derived from the cipher key using Rijndael's key schedule. 
* AES requires a separate 128-bit round key block for each round plus one more.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void KeyExpansion(unsigned char *inputKey, unsigned char *expandedKey);


/*
* a non-linear substitution step where each byte is replaced with another according to a lookup table.
* Lookup table link [https://en.wikipedia.org/wiki/Rijndael_S-box]
*/
void SubBytes(unsigned char *state);


/*
* a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void ShiftRows(unsigned char *state);

/*
* a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void MixColumn(unsigned char *state);


/*
 * In the AddRoundKey step, the subkey is combined with the state. For each round, 
 * a subkey is derived from the main key using Rijndael's key schedule; each subkey 
 * is the same size as the state. The subkey is added by combining each byte of the 
 * state with the corresponding byte of the subkey using bitwise XOR
 * [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void AddRoundKey(unsigned char *state, unsigned char *roundkey);

/*
 * encrypt a block of 16 bytes 
*/
void aesencrypt(unsigned char *message, unsigned char *expandedKey);

#endif
