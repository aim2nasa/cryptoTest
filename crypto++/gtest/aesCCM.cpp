#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/ccm.h>
#include "util.h"

#define TAG_SIZE 8
#define CCM_MAX_IV_SIZE 13

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
