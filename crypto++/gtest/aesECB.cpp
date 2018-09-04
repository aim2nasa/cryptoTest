#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
 
TEST(AesECBTest, encryptDescrypt_Key128bit) { 
	const unsigned int keySize = CryptoPP::AES::DEFAULT_KEYLENGTH;
	ASSERT_EQ(keySize,16);
	byte key[keySize];
	memset(key,0,keySize);

	std::string plainText = "This is test";

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
	e.SetKey(key,sizeof(key));

	std::string cipherText;
	CryptoPP::StringSource(plainText,true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(cipherText)
		)
	);
	std::cout<<"plain text:"<<plainText<<std::endl;
	std::cout<<"cipher text:"<<cipherText<<std::endl;
	EXPECT_NE(plainText,cipherText);
}
