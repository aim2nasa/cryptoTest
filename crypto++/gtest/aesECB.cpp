#include <gtest/gtest.h>
#include <cryptopp/aes.h>
 
TEST(AesECBTest, encryptDescrypt_Key128bit) { 
	const unsigned int keySize = CryptoPP::AES::DEFAULT_KEYLENGTH;
	ASSERT_EQ(keySize,16);
	byte key[keySize];
	memset(key,0,keySize);

	std::string plainText = "This is test";
}
