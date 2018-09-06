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

	std::string header = "head";
	std::string plainText = "AE CCM test";
	std::cout<<"plain text:"<<plainText<<std::endl;

	//encryption
	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Encryption e;
	e.SetKeyWithIV(key,sizeof(key),iv,sizeof(iv));
	e.SpecifyDataLengths(header.size(),plainText.size(),0);

	std::string cipherText;
	CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(cipherText) );

	ef.ChannelPut("AAD",(const byte*)header.data(),header.size());
	ef.ChannelMessageEnd("AAD");

	ef.ChannelPut("",(const byte*)plainText.data(),plainText.size());
	ef.ChannelMessageEnd("");

	show("cipher text:",cipherText);

	std::cout<<"plainText size:"<<plainText.size()<<std::endl;
	std::cout<<"cipherText size:"<<cipherText.size()<<std::endl;

	//decryption
	std::string enc = cipherText.substr(0,cipherText.size()-TAG_SIZE);
	std::string tag = cipherText.substr(cipherText.size()-TAG_SIZE);

	std::cout<<"enc size:"<<enc.size()<<std::endl;
	std::cout<<"tag size:"<<tag.size()<<std::endl;

	EXPECT_EQ(cipherText.size(),enc.size()+tag.size());
	EXPECT_EQ(TAG_SIZE,tag.size());

	CryptoPP::CCM<CryptoPP::AES,TAG_SIZE>::Decryption d;
	d.SetKeyWithIV(key,sizeof(key),iv,sizeof(iv));
	d.SpecifyDataLengths(header.size(),enc.size(),0);

	CryptoPP::AuthenticatedDecryptionFilter df(d,NULL,
		CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION);
	
	df.ChannelPut("AAD",(const byte*)header.data(),header.size());
	df.ChannelMessageEnd("AAD");

	df.ChannelPut("",(const byte*)enc.data(),enc.size());
	df.ChannelPut("",(const byte*)tag.data(),tag.size());
	df.ChannelMessageEnd("");

	bool b = df.GetLastResult();
	EXPECT_EQ(b,true);

	df.SetRetrievalChannel("");
	size_t n = (size_t)df.MaxRetrievable();
	std::cout<<"retrieved:"<<n<<std::endl;

	std::string recovered;
	recovered.resize(n);

	df.Get( (byte*)recovered.data(),n); 
	std::cout<<"recovered:"<<recovered<<std::endl;
	EXPECT_EQ(recovered,plainText);
}

TEST(AesCCMTest, encryptDescrypt) { 
	try{
		aesCcmEncDec(16); //128bit(16byte)
		aesCcmEncDec(24); //192bit(24byte)
		aesCcmEncDec(32); //256bit(32byte)
	}catch(const CryptoPP::Exception& e){
		FAIL();
		std::cerr<<e.what()<<std::endl;
	}
}
