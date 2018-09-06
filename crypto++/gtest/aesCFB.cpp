#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include "util.h"

void aesCfbEncDec(unsigned int keySizeInBytes) { 
	const unsigned int keySize = keySizeInBytes;
	byte key[keySize],iv[CryptoPP::AES::BLOCKSIZE];
	memset(key,0,sizeof(key));
	memset(iv,0,sizeof(iv));

	std::string plainText = "CFB Mode test";

	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption e;
	e.SetKeyWithIV(key,sizeof(key),iv);

	//encrypt given plainText
	std::string cipherText;
	CryptoPP::StringSource(plainText,true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(cipherText)
		)
	);
	print("plain text:"+plainText);
	show("cipher text:",cipherText);
	EXPECT_NE(plainText,cipherText);

	//decrypt cipherText
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption d;
	d.SetKeyWithIV(key,sizeof(key),iv);

	std::string recoveredText;
	CryptoPP::StringSource(cipherText,true,
		new CryptoPP::StreamTransformationFilter(d,
			new CryptoPP::StringSink(recoveredText)
		)
	);
	print("recovered text:"+recoveredText);

	//compare decrypt result with the given plainText
	EXPECT_EQ(plainText,recoveredText);
}

TEST(AesCFBTest, encryptDescrypt) { 
	aesCfbEncDec(16); //128bit(16byte)
	aesCfbEncDec(24); //192bit(24byte)
	aesCfbEncDec(32); //256bit(32byte)
}

TEST(AesCFBTest, encryptDescryptUnsupportedKeySize) { 
	unsigned int keyLen=17;
	try{
		aesCfbEncDec(keyLen);
	}catch(const CryptoPP::Exception& e){
		print(e.what());
		char msg[256];
		sprintf(msg,"AES/CFB: %d is not a valid key length",keyLen);
		EXPECT_EQ(std::string(msg),e.what());
	}
}
