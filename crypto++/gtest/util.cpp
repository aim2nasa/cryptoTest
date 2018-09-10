#include "util.h"
#include <cryptopp/hex.h>

std::string toHexStr(std::string value)
{
	std::string encoded;
	CryptoPP::StringSource(value,true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		)
	);
	return encoded;
}

void show(std::string name,std::string value)
{
#ifdef DEBUG
	std::cout<<name<<toHexStr(value)<<std::endl;
#endif
}

void print(std::string str)
{
#ifdef DEBUG
	std::cout<<str<<std::endl;
#endif
}
