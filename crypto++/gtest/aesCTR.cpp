#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include "util.h"

void aesCtrEncDec(unsigned int keySizeInBytes) { 
	const unsigned int keySize = keySizeInBytes;
	byte key[keySize],iv[CryptoPP::AES::BLOCKSIZE];
	memset(key,0,sizeof(key));
	memset(iv,0,sizeof(iv));

	std::string plainText = "CTR Mode test";

	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
	e.SetKeyWithIV(key,sizeof(key),iv);

	//encrypt given plainText
	std::string cipherText;
	CryptoPP::StringSource(plainText,true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(cipherText)
		)
	);
	std::cout<<"plain text:"<<plainText<<std::endl;
	show("cipher text:",cipherText);
	EXPECT_NE(plainText,cipherText);

	//decrypt cipherText
	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
	d.SetKeyWithIV(key,sizeof(key),iv);

	std::string recoveredText;
	CryptoPP::StringSource(cipherText,true,
		new CryptoPP::StreamTransformationFilter(d,
			new CryptoPP::StringSink(recoveredText)
		)
	);
	std::cout<<"recovered text:"<<recoveredText<<std::endl;

	//compare decrypt result with the given plainText
	EXPECT_EQ(plainText,recoveredText);
}

TEST(AesCTRTest, encryptDescrypt) { 
	aesCtrEncDec(16); //128bit(16byte)
	aesCtrEncDec(24); //192bit(24byte)
	aesCtrEncDec(32); //256bit(32byte)
}

TEST(AesCTRTest, encryptDescryptUnsupportedKeySize) { 
	unsigned int keyLen=17;
	try{
		aesCtrEncDec(keyLen);
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		char msg[256];
		sprintf(msg,"AES/CTR: %d is not a valid key length",keyLen);
		EXPECT_EQ(std::string(msg),e.what());
	}
}
