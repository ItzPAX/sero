#include "pqsign.hpp"
#include <iostream>

int main()
{
	pqsign::key_pair pair = pqsign::generate_key_pair();
	std::string signature = pqsign::sign("Hallo Welt!", pair);
	std::cout << "sig: " << signature << std::endl;
	std::cout << "VALID: " << pqsign::verify("H1allo Welt!", signature, pair);
}