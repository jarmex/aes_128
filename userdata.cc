/**************************************************************
  File:          userdata.cc
  Description:   A program to implement the AES-128 encryption. 
  Author:        James Amo (Group 6)
  Organization:  IUSB, Computer and Information Sciences
  Date:          September 2018
***************************************************************/

#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include "aes.h"
#include "AESConstants.h"

using namespace std;
// global variables
string filename;
string password;
string outputfilename;
unsigned char expandedKey[AES_ROUND_KEY_SIZE];

// capture user input
void GetUserInput()
{
  string fname, pword;
  cout << "Enter the cipher file: ";
  getline(cin, fname);
  do
  {
    cout << "Enter the 16-character password: ";
    getline(cin, pword);
  } while (pword.length() != 16);
  // validate if the password is
  filename = fname;
  password = pword;
  outputfilename = "cipher_" + filename;
}

// write the encrypted file to file
void EncryptString(string strmessage)
{
  int originalLen = strmessage.length() + 1;
  unsigned char *message = new unsigned char[originalLen];
  strcpy((char *)message, strmessage.c_str());
  // copy the password
  unsigned char *key = new unsigned char[AES_BLOCK_SIZE];
  strcpy((char *)key, password.c_str());

  // int originalLen = strlen((const char *)message);
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

for (int i = 0; i < lenOfPaddingMessage; i++)
  {
    cout <<  paddedMessage[i];
  }
  cout << endl;
  // expand the key
  KeyExpansion(key, expandedKey);

  // encrypt padded message
  for (int i = 0; i < lenOfPaddingMessage; i += AES_BLOCK_SIZE)
  {
    aesencrypt(paddedMessage + i, expandedKey);
    // aesencrypt(paddedMessage + i, expandedKeys);
  }

  ofstream writefile(outputfilename, ios::app);
  if (!writefile)
  {
    cout << "Error Opening File" << endl;
    return;
  }
  // writefile << strmessage << endl;
  for (int i = 0; i < lenOfPaddingMessage; i++)
  {
    writefile << setw(4) << (int)paddedMessage[i]; 
    if ((i + 1) % AES_BLOCK_SIZE == 0)  writefile << endl;
  }
  writefile.close();
  // for (int i = 0; i < lenOfPaddingMessage; i++)
  // {
  //   printf("%02X ", paddedMessage[i]);
  // }
  // cout << endl;

  delete[] paddedMessage;
  delete[] key;
}

// read the data from the file and encrypt the content
void EncryptFile()
{
  // read the data from file and store in the vector
  ifstream readfile(filename);
  string usrinput = "";
  string line;
  while (getline(readfile, line))
  {
    usrinput += line ;
  }
  readfile.close();
  cout << usrinput << endl;
    EncryptString(usrinput);
}

