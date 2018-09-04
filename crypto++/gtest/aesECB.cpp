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
 
TEST(AesECBTest, encryptDescrypt_Key128bit) { 
	const unsigned int keySize = CryptoPP::AES::DEFAULT_KEYLENGTH;
	ASSERT_EQ(keySize,16);
	byte key[keySize];
	memset(key,0,keySize);

	std::string plainText = "ECB Mode test";

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
	e.SetKey(key,sizeof(key));

	std::string cipherText;
	CryptoPP::StringSource(plainText,true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(cipherText)
		)
	);
	std::cout<<"plain text:"<<plainText<<std::endl;
	show("cipher text:",cipherText);
	EXPECT_NE(plainText,cipherText);

	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
	d.SetKey(key,sizeof(key));

	std::string recoveredText;
	CryptoPP::StringSource(cipherText,true,
		new CryptoPP::StreamTransformationFilter(d,
			new CryptoPP::StringSink(recoveredText)
		)
	);
	std::cout<<"recovered text:"<<recoveredText<<std::endl;
	EXPECT_EQ(plainText,recoveredText);
}
