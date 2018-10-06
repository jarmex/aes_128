/**************************************************************
  File:          aes.cc
  Description:   A program to implement the AES-128 encryption. 
  Author:        James Amo (Group 6)
  Organization:  IUSB, Computer and Information Sciences
  Date:          September 2018
***************************************************************/

#include <stdint.h>
#include <stdio.h>
#include "AESConstants.h"
#include "aes.h"

// https://en.wikipedia.org/wiki/Finite_field_arithmetic
unsigned char mul2(unsigned char a)
{
  return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

/*
* used in the implementation of the key expansion
*/
void KeyExpansionCore(unsigned char *in, unsigned char i)
{
  // rotate left
  unsigned int *q = (unsigned int *)in;
  *q = (*q >> 8) | ((*q & 0xff) << 24);

  // s-box four bytes lookup
  for (int j = 0; j < 4; j++)
  {
    in[j] = SBOX[in[j]];
  }
  //rcon
  in[0] ^= RCON[i];
}
/*
* round keys are derived from the cipher key using Rijndael's key schedule. 
* AES requires a separate 128-bit round key block for each round plus one more.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void KeyExpansion(unsigned char *inputKey, unsigned char *expandedKey)
{
  // the first 16 bytes are the original key:
  for (int i = 0; i < 16; i++)
  {
    expandedKey[i] = inputKey[i];
  }
  // variables
  int bytesGenerated = 16; // number of bytes generated so far
  int rconIteration = 1;   // RCON iteration begin at 1
  unsigned char tmp[4];    // Temporary storage for core

  while (bytesGenerated < AES_ROUND_KEY_SIZE)
  {
    // read the last 4 bytes generated for the core
    for (int i = 0; i < 4; i++)
    {
      tmp[i] = expandedKey[i + bytesGenerated - 4];
    }
    // perform the core once for each 16 byte key
    if (bytesGenerated % 16 == 0)
    {
      KeyExpansionCore(tmp, rconIteration++);
    }
    // XOR tmp  with [bytesGenerated - 16], and store in expandedKeys

    for (unsigned char a = 0; a < 4; a++)
    {
      expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ tmp[a];
      bytesGenerated++;
    }
  }
}

/*
* a non-linear substitution step where each byte is replaced with another according to a lookup table.
* Lookup table link [https://en.wikipedia.org/wiki/Rijndael_S-box]
*/
void SubBytes(unsigned char *state)
{
  for (int i = 0; i < AES_BLOCK_SIZE; i++)
  {
    *(state + i) = SBOX[*(state + i)];
    // state[i] = SBOX[state[i]];
  }
}

/*
* a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void ShiftRows(unsigned char *state)
{
  unsigned char temp;
  // row1
  temp = *(state + 1);
  *(state + 1) = *(state + 5);
  *(state + 5) = *(state + 9);
  *(state + 9) = *(state + 13);
  *(state + 13) = temp;
  // row2
  temp = *(state + 2);
  *(state + 2) = *(state + 10);
  *(state + 10) = temp;
  temp = *(state + 6);
  *(state + 6) = *(state + 14);
  *(state + 14) = temp;
  // row3
  temp = *(state + 15);
  *(state + 15) = *(state + 11);
  *(state + 11) = *(state + 7);
  *(state + 7) = *(state + 3);
  *(state + 3) = temp;
}

/*
* a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
* [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void MixColumn(unsigned char *state)
{
  unsigned char t;
  unsigned char tmp[16];
  /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
  for (int i = 0; i < AES_BLOCK_SIZE; i += 4)
  {
    t = state[i] ^ state[i + 1] ^ state[i + 2] ^ state[i + 3];
    tmp[i] = mul2(state[i] ^ state[i + 1]) ^ state[i] ^ t;
    tmp[i + 1] = mul2(state[i + 1] ^ state[i + 2]) ^ state[i + 1] ^ t;
    tmp[i + 2] = mul2(state[i + 2] ^ state[i + 3]) ^ state[i + 2] ^ t;
    tmp[i + 3] = mul2(state[i + 3] ^ state[i]) ^ state[i + 3] ^ t;
  }
  // copy the result back to the state
  for (int i = 0; i < AES_BLOCK_SIZE; i++)
  {
    state[i] = tmp[i];
  }
}

/*
 * In the AddRoundKey step, the subkey is combined with the state. For each round, 
 * a subkey is derived from the main key using Rijndael's key schedule; each subkey 
 * is the same size as the state. The subkey is added by combining each byte of the 
 * state with the corresponding byte of the subkey using bitwise XOR
 * [link] https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/
void AddRoundKey(unsigned char *state, unsigned char *roundkey)
{
  // cout << "RoundKey #" << index <<" = ";
  for (int i = 0; i < AES_BLOCK_SIZE; i++)
  {
    state[i] ^= roundkey[i];
    // printf("%02x ", roundkey[i]);
  }
  // cout << endl;
}

/*
 * encrypt a block of 16 bytes 
*/
void aesencrypt(unsigned char *message, unsigned char *expandedKey)
{
  int numberOfRound = AES_ROUNDS - 1;
  unsigned char state[16];

  for (int i = 0; i < 16; i++)
  {
    state[i] = message[i];
  }
  // first AddRoundKey
  AddRoundKey(state, expandedKey); // Add round key

  for (int i = 0; i < numberOfRound; i++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumn(state);
    AddRoundKey(state, expandedKey + (16 * (i + 1)));
  }
  // Final Round
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, expandedKey + 160);

  // copy the encrypted message from the state

  for (int i = 0; i < 16; i++)
  {
    message[i] = state[i];
  }
}
