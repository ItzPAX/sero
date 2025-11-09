#include "block.hpp"
#include <iostream>

int main()
{
	pqsign::key_pair pair = pqsign::generate_key_pair();

	block_t bl;
	bl.add_tx(pair, 1250, "test_wallet");
	bl.hex_prev = "0";
	bl.nonce = 1;
	
	bl.get_hash();

	for (auto& tx : bl.txs)
	{
		std::cout << tx.signature << std::endl;
	}

	bl.mine();
	std::cout << bl.get_hash() << std::endl;
}