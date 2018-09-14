#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include "util.h"

class aesGCMTest: public ::testing::Test {
public:
	std::string enc(int tagSize,std::string aad,std::string plainText);
	bool dec(int tagSize,std::string aad,std::string cipherText,std::string& decodedText);
	void encTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText,std::string cipherTextHexStr);
	void encDecTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText);
	CryptoPP::AuthenticatedSymmetricCipher* asEncryption(int tagSize);
	CryptoPP::AuthenticatedSymmetricCipher* asDecryption(int tagSize);

	void setUp(int tagSize,int keySize,int ivSize) {
		keySize_ = keySize;
		ivSize_ = ivSize;

		key_ = new byte[keySize_];
		iv_ = new byte[ivSize_];
		memset(key_,0,keySize_);
		memset(iv_,0,ivSize_);
		encCipher_ = asEncryption(tagSize);
		decCipher_ = asDecryption(tagSize);
		encCipher_->SetKeyWithIV(key_,keySize_,iv_,ivSize_);
		decCipher_->SetKeyWithIV(key_,keySize_,iv_,ivSize_);
	}
	void tearDown(){
		delete decCipher_;
		delete encCipher_;
		delete [] iv_;
		delete [] key_;
	}

	int keySize_,ivSize_;
	byte *key_,*iv_;
	CryptoPP::AuthenticatedSymmetricCipher* encCipher_;
	CryptoPP::AuthenticatedSymmetricCipher* decCipher_;

	static int Keys[];
	static int IVs[];
	static int Tags[];
};

int aesGCMTest::Keys[]={16,24,32};
int aesGCMTest::IVs[]={7,8,9,10,11,12,13};
int aesGCMTest::Tags[]={4,6,8,10,12,14,16};

std::string aesGCMTest::enc(int tagSize,std::string aad,std::string plainText){
	encCipher_->SpecifyDataLengths(aad.size(),plainText.size(),0);

	std::string cipherText;
	CryptoPP::AuthenticatedEncryptionFilter ef(*encCipher_,new CryptoPP::StringSink(cipherText) );

	ef.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	ef.ChannelMessageEnd("AAD");

	ef.ChannelPut("",(const byte*)plainText.data(),plainText.size());
	ef.ChannelMessageEnd("");
	return cipherText;
}

bool aesGCMTest::dec(int tagSize,std::string aad,std::string cipherText,std::string& decodedText){
	std::string enc = cipherText.substr(0,cipherText.size()-tagSize);
	std::string tag = cipherText.substr(cipherText.size()-tagSize);

	EXPECT_EQ(cipherText.size(),enc.size()+tag.size());
	EXPECT_EQ(tag.size(),tagSize);

	decCipher_->SpecifyDataLengths(aad.size(),enc.size(),0);

	CryptoPP::AuthenticatedDecryptionFilter df(*decCipher_,NULL,
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

void aesGCMTest::encTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText,std::string cipherTextHexStr){
	setUp(tagSize,keySize,ivSize);
	EXPECT_EQ(toHexStr(enc(tagSize,aad,plainText)),cipherTextHexStr);
	tearDown();
}

void aesGCMTest::encDecTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText){
	setUp(tagSize,keySize,ivSize);
	std::string recoveredText;
	EXPECT_EQ(dec(tagSize,aad,enc(tagSize,aad,plainText),recoveredText),true);
	EXPECT_EQ(recoveredText,plainText);
	tearDown();
}

CryptoPP::AuthenticatedSymmetricCipher* aesGCMTest::asEncryption(int tagSize){
	CryptoPP::AuthenticatedSymmetricCipher* p = new CryptoPP::GCM<CryptoPP::AES>::Encryption;
	return p;
}

CryptoPP::AuthenticatedSymmetricCipher* aesGCMTest::asDecryption(int tagSize){
	CryptoPP::AuthenticatedSymmetricCipher* p = new CryptoPP::GCM<CryptoPP::AES>::Decryption;
	return p;
}

TEST_F(aesGCMTest,encrypt) {
	try{
		encTest(8,16,13,"AAD","AE GCM test","7EAC7BA8272B0DA894E9E2A8CF90E5B9EF123B3D36301639C6B60C");
		encTest(8,24,13,"AAD","AE GCM test","34A0E5B46BC10DD2812F4B8B9FBA345773E213735912B686FEE4A0");
		encTest(8,32,13,"AAD","AE GCM test","90441CC8145ABDEBD7FBFF58DABAFE407A58730F38A5CC52F6BB3B");
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}

TEST_F(aesGCMTest,encryptDecrypt) {
	try{
		for(int i=0;i<sizeof(Keys)/sizeof(int);i++)
			for(int j=0;j<sizeof(IVs)/sizeof(int);j++)
				for(int k=0;k<sizeof(Tags)/sizeof(int);k++){
					encDecTest(Tags[k],Keys[i],IVs[j],"AAD","AE GCM test");
					char msg[256];
					sprintf(msg,"encryptDecrypt for Key Size:%d byte,IV Size:%d byte Tag size:%d done",Keys[i],IVs[j],Tags[k]);
					print(msg);
			}

	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}
