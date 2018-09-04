#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

void show(std::string name,std::string value)
{
	std::string encoded;
	CryptoPP::StringSource(value,true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		)
	);
	std::cout<<name<<encoded<<std::endl;
}

void aesEcbEncDec(unsigned int keySizeInBytes) { 
	const unsigned int keySize = keySizeInBytes;
	ASSERT_EQ(keySize,16);
	byte key[keySize];
	memset(key,0,keySize);

	std::string plainText = "ECB Mode test";

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
	e.SetKey(key,sizeof(key));

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
	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
	d.SetKey(key,sizeof(key));

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

TEST(AesECBTest, encryptDescrypt) { 
	aesEcbEncDec(CryptoPP::AES::DEFAULT_KEYLENGTH); //128bit(16byte)
}
