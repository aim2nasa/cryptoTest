#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/ccm.h>
#include "util.h"

#define TAG_SIZE 8
#define CCM_MAX_IV_SIZE 13

class aesCCMTest: public ::testing::Test {
public:
	std::string enc(std::string aad,std::string plainText);
	bool dec(std::string aad,std::string cipherText,std::string& decodedText);
	void encTest(int keySize,int ivSize,std::string aad,std::string plainText,std::string cipherTextHexStr);
	void encDecTest(int keySize,int ivSize,std::string aad,std::string plainText);

	void SetUp(int keySize,int ivSize) {
		keySize_ = keySize;
		ivSize_ = ivSize;

		key_ = new byte[keySize_];
		iv_ = new byte[ivSize_];
		memset(key_,0,keySize_);
		memset(iv_,0,ivSize_);
	}
	virtual void TearDown() {
		delete [] iv_;
		delete [] key_;
	}

	int keySize_,ivSize_;
	byte *key_,*iv_;
};

std::string aesCCMTest::enc(std::string aad,std::string plainText){
	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Encryption e;
	e.SetKeyWithIV(key_,keySize_,iv_,ivSize_);
	e.SpecifyDataLengths(aad.size(),plainText.size(),0);

	std::string cipherText;
	CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(cipherText) );

	ef.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	ef.ChannelMessageEnd("AAD");

	ef.ChannelPut("",(const byte*)plainText.data(),plainText.size());
	ef.ChannelMessageEnd("");
	return cipherText;
}

bool aesCCMTest::dec(std::string aad,std::string cipherText,std::string& decodedText){
	std::string enc = cipherText.substr(0,cipherText.size()-TAG_SIZE);
	std::string tag = cipherText.substr(cipherText.size()-TAG_SIZE);

	EXPECT_EQ(cipherText.size(),enc.size()+tag.size());
	EXPECT_EQ(tag.size(),TAG_SIZE);

	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Decryption d;
	d.SetKeyWithIV(key_,keySize_,iv_,ivSize_);
	d.SpecifyDataLengths(aad.size(),enc.size(),0);

	CryptoPP::AuthenticatedDecryptionFilter df(d,NULL,
		CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION);
	
	df.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	df.ChannelMessageEnd("AAD");

	df.ChannelPut("",(const byte*)enc.data(),enc.size());
	df.ChannelPut("",(const byte*)tag.data(),tag.size());
	df.ChannelMessageEnd("");

	bool b = df.GetLastResult();
	if(!b) return false;

	df.SetRetrievalChannel("");
	decodedText.resize((size_t)df.MaxRetrievable());
	df.Get( (byte*)decodedText.data(),decodedText.size()); 

	return true;
}

void aesCCMTest::encTest(int keySize,int ivSize,std::string aad,std::string plainText,std::string cipherTextHexStr){
	SetUp(keySize,ivSize);
	EXPECT_EQ(toHexStr(enc(aad,plainText)),cipherTextHexStr);
}

void aesCCMTest::encDecTest(int keySize,int ivSize,std::string aad,std::string plainText){
	SetUp(keySize,ivSize);
	std::string recoveredText;
	EXPECT_EQ(dec(aad,enc(aad,plainText),recoveredText),true);
	EXPECT_EQ(recoveredText,plainText);
}

TEST_F(aesCCMTest,encrypt) {
	try{
		encTest(16,13,"AAD","AE CCM test","943DD24E43D8AC18351D42006FC5A8D65ABDB2");
		encTest(24,13,"AAD","AE CCM test","66988B77828B17B0310F0E08F7837A9041121A");
		encTest(32,13,"AAD","AE CCM test","9CDB64EB4BB626AC2D4F5A6483C1EC756305C4");
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}

TEST_F(aesCCMTest,encryptDecrypt) {
	try{
		encDecTest(16,13,"AAD","AE CCM test");
		encDecTest(24,13,"AAD","AE CCM test");
		encDecTest(32,13,"AAD","AE CCM test");
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}
