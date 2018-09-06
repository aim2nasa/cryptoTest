#include "util.h"
#include <cryptopp/hex.h>

void show(std::string name,std::string value)
{
#ifdef DEBUG
	std::string encoded;
	CryptoPP::StringSource(value,true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		)
	);
	std::cout<<name<<encoded<<std::endl;
#endif
}

void print(std::string str)
{
#ifdef DEBUG
	std::cout<<str<<std::endl;
#endif
}
