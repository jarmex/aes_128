/**************************************************************
  File:          main.cc
  Description:   A program to implement the AES-128 encryption. 
  Author:        James Amo (Group 6)
  Organization:  IUSB, Computer and Information Sciences
  Date:          September 2018
***************************************************************/

#include <cstdlib>
#include <pthread.h>
#include <ctime>
#include <iostream>
using namespace std;
#include "aes.h"
#include "userdata.h"

void aesprototyping()
{
  unsigned char expandedKey[AES_ROUND_KEY_SIZE];
  unsigned char message[] = "This is a message we will encrypt with AES!";
  unsigned char key[] = "ThisisMyPassword";


  int originalLen = strlen((const char *)message);

  int lenOfPaddingMessage = originalLen;
  // PKCS#5 padding.
  // Padding is a sequence of identical bytes, each has value
  // equal to the length (in bytes) of the padding
  int paddednum = lenOfPaddingMessage % AES_BLOCK_SIZE;

  if (paddednum != 0)
  {
    lenOfPaddingMessage = (lenOfPaddingMessage / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
  }

  unsigned char *paddedMessage = new unsigned char[lenOfPaddingMessage];

  // pad the messages with 0 if the message is not divisible by 16
  for (int i = 0; i < lenOfPaddingMessage; i++)
  {
    if (i >= originalLen)
      paddedMessage[i] = 0;
    else
      paddedMessage[i] = message[i];
  }

  // expand the key
  KeyExpansion(key, expandedKey);

  // encrypt padded message
  for (int i = 0; i < lenOfPaddingMessage; i += AES_BLOCK_SIZE)
  {
    aesencrypt(paddedMessage + i, expandedKey);
    // aesencrypt(paddedMessage + i, expandedKeys);
  }

  for (int i = 0; i < lenOfPaddingMessage; i++)
  {
    printf("%02X ", paddedMessage[i]);
  }
  cout << endl;
  for (int i = 0; i < lenOfPaddingMessage; i++)
  {
    if ((i + 1) % AES_BLOCK_SIZE == 0)
    {
      printf("%03d \n", paddedMessage[i]);
    }
    else
    {
      printf("%03d ", paddedMessage[i]);
    }
  }
  cout << endl;
  delete[] paddedMessage;
}
int main()
{
  GetUserInput();
  EncryptFile();
  // aesprototyping();
  return 0;
}
