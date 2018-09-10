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

	virtual void SetUp() {
		keySize_ = 32;
		ivSize_ = CCM_MAX_IV_SIZE;

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

TEST_F(aesCCMTest,encrypt) {
	std::string plainText = "AE CCM test";
	std::string cipherText = enc("AAD",plainText);

	EXPECT_EQ(plainText,"AE CCM test");
	EXPECT_EQ(toHexStr(cipherText),"9CDB64EB4BB626AC2D4F5A6483C1EC756305C4");
}

TEST_F(aesCCMTest,decrypt) {
	std::string recoveredText;
	EXPECT_EQ(dec("AAD",enc("AAD","AE CCM test"),recoveredText),true);
	EXPECT_EQ(recoveredText,"AE CCM test");
}

void aesCcmEncDec(unsigned int keySizeInBytes){
	const unsigned int keySize = keySizeInBytes;

	byte key[keySize],iv[CCM_MAX_IV_SIZE];
	memset(key,0,sizeof(key));
	memset(iv,0,sizeof(iv));

	std::string aad = "AdditionalAuthenticatedData";
	std::string plainText = "AE CCM test";
	print("plain text:"+plainText);

	//encryption
	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Encryption e;
	e.SetKeyWithIV(key,sizeof(key),iv,sizeof(iv));
	e.SpecifyDataLengths(aad.size(),plainText.size(),0);

	std::string cipherText;
	CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(cipherText) );

	ef.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	ef.ChannelMessageEnd("AAD");

	ef.ChannelPut("",(const byte*)plainText.data(),plainText.size());
	ef.ChannelMessageEnd("");

	show("cipher text:",cipherText);

	EXPECT_EQ(plainText.size(),11);
	EXPECT_EQ(cipherText.size(),19);

	//decryption
	std::string enc = cipherText.substr(0,cipherText.size()-TAG_SIZE);
	std::string tag = cipherText.substr(cipherText.size()-TAG_SIZE);

	EXPECT_EQ(cipherText.size(),enc.size()+tag.size());
	EXPECT_EQ(enc.size(),plainText.size());
	EXPECT_EQ(tag.size(),TAG_SIZE);

	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Decryption d;
	d.SetKeyWithIV(key,sizeof(key),iv,sizeof(iv));
	d.SpecifyDataLengths(aad.size(),enc.size(),0);

	CryptoPP::AuthenticatedDecryptionFilter df(d,NULL,
		CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION);
	
	df.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	df.ChannelMessageEnd("AAD");

	df.ChannelPut("",(const byte*)enc.data(),enc.size());
	df.ChannelPut("",(const byte*)tag.data(),tag.size());
	df.ChannelMessageEnd("");

	bool b = df.GetLastResult();
	EXPECT_EQ(b,true);

	df.SetRetrievalChannel("");
	size_t n = (size_t)df.MaxRetrievable();
	print("retrieved:"+n);

	std::string recovered;
	recovered.resize(n);

	df.Get( (byte*)recovered.data(),n); 
	print("recovered:"+recovered);
	EXPECT_EQ(recovered,plainText);
}

TEST(AesCCMTest, encryptDescrypt) { 
	try{
		aesCcmEncDec(16); //128bit(16byte)
		aesCcmEncDec(24); //192bit(24byte)
		aesCcmEncDec(32); //256bit(32byte)
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}
