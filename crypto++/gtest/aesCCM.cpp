#include <gtest/gtest.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/ccm.h>
#include "util.h"

class aesCCMTest: public ::testing::Test {
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

int aesCCMTest::Keys[]={16,24,32};
int aesCCMTest::IVs[]={7,8,9,10,11,12,13};
int aesCCMTest::Tags[]={4,6,8,10,12,14,16};

std::string aesCCMTest::enc(int tagSize,std::string aad,std::string plainText){
	encCipher_->SpecifyDataLengths(aad.size(),plainText.size(),0);

	std::string cipherText;
	CryptoPP::AuthenticatedEncryptionFilter ef(*encCipher_,new CryptoPP::StringSink(cipherText) );

	ef.ChannelPut("AAD",(const byte*)aad.data(),aad.size());
	ef.ChannelMessageEnd("AAD");

	ef.ChannelPut("",(const byte*)plainText.data(),plainText.size());
	ef.ChannelMessageEnd("");
	return cipherText;
}

bool aesCCMTest::dec(int tagSize,std::string aad,std::string cipherText,std::string& decodedText){
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

void aesCCMTest::encTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText,std::string cipherTextHexStr){
	setUp(tagSize,keySize,ivSize);
	EXPECT_EQ(toHexStr(enc(tagSize,aad,plainText)),cipherTextHexStr);
	tearDown();
}

void aesCCMTest::encDecTest(int tagSize,int keySize,int ivSize,std::string aad,std::string plainText){
	setUp(tagSize,keySize,ivSize);
	std::string recoveredText;
	EXPECT_EQ(dec(tagSize,aad,enc(tagSize,aad,plainText),recoveredText),true);
	EXPECT_EQ(recoveredText,plainText);
	tearDown();
}

CryptoPP::AuthenticatedSymmetricCipher* aesCCMTest::asEncryption(int tagSize){
	CryptoPP::AuthenticatedSymmetricCipher* p = NULL;
	switch(tagSize){
	case 4:
		p = new CryptoPP::CCM<CryptoPP::AES,4>::Encryption;
		break;
	case 6:
		p = new CryptoPP::CCM<CryptoPP::AES,6>::Encryption;
		break;
	case 8:
		p = new CryptoPP::CCM<CryptoPP::AES,8>::Encryption;
		break;
	case 10:
		p = new CryptoPP::CCM<CryptoPP::AES,10>::Encryption;
		break;
	case 12:
		p = new CryptoPP::CCM<CryptoPP::AES,12>::Encryption;
		break;
	case 14:
		p = new CryptoPP::CCM<CryptoPP::AES,14>::Encryption;
		break;
	case 16:
		p = new CryptoPP::CCM<CryptoPP::AES,16>::Encryption;
		break;
	}
	return p;
}

CryptoPP::AuthenticatedSymmetricCipher* aesCCMTest::asDecryption(int tagSize){
	CryptoPP::AuthenticatedSymmetricCipher* p = NULL;
	switch(tagSize){
	case 4:
		p = new CryptoPP::CCM<CryptoPP::AES,4>::Decryption;
		break;
	case 6:
		p = new CryptoPP::CCM<CryptoPP::AES,6>::Decryption;
		break;
	case 8:
		p = new CryptoPP::CCM<CryptoPP::AES,8>::Decryption;
		break;
	case 10:
		p = new CryptoPP::CCM<CryptoPP::AES,10>::Decryption;
		break;
	case 12:
		p = new CryptoPP::CCM<CryptoPP::AES,12>::Decryption;
		break;
	case 14:
		p = new CryptoPP::CCM<CryptoPP::AES,14>::Decryption;
		break;
	case 16:
		p = new CryptoPP::CCM<CryptoPP::AES,16>::Decryption;
		break;
	}
	return p;
}

TEST_F(aesCCMTest,encrypt) {
	std::string adata(16, (char)0x00);
	try{
		encTest(8,16,13,adata,"AE CCM test","943DD24E43D8AC18351D42FD937A4A4F24080B");
		encTest(8,24,13,adata,"AE CCM test","66988B77828B17B0310F0EED3A8F65720A37A3");
		encTest(8,32,13,adata,"AE CCM test","9CDB64EB4BB626AC2D4F5A7B28F376BF57B95B");
	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}

TEST_F(aesCCMTest,encryptDecrypt) {
	std::string adata(16, (char)0x00);
	try{
		for(int i=0;i<sizeof(Keys)/sizeof(int);i++)
			for(int j=0;j<sizeof(IVs)/sizeof(int);j++)
				for(int k=0;k<sizeof(Tags)/sizeof(int);k++){
					encDecTest(Tags[k],Keys[i],IVs[j],adata,"AE CCM test");
					char msg[256];
					sprintf(msg,"encryptDecrypt for Key Size:%d byte,IV Size:%d byte Tag size:%d done",Keys[i],IVs[j],Tags[k]);
					print(msg);
			}

	}catch(const CryptoPP::Exception& e){
		std::cerr<<e.what()<<std::endl;
		FAIL();
	}
}
