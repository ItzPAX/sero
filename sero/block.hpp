#pragma once
#include <vector>
#include <iostream>

#include "pqsign.hpp"
#include "picosha2.h"

struct transaction
{
	std::string from;
	std::string to;
	std::string signature;
	uint64_t sum; // as eurocent

	std::string get_hash()
	{
		std::string src_string = from;
		src_string.append(to);
		src_string.append(std::to_string(sum));

		std::vector<unsigned char> hash(picosha2::k_digest_size);
		picosha2::hash256(src_string.begin(), src_string.end(), hash.begin(), hash.end());

		std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());
		return hex_str;
	}
};

struct block_t
{
	uint64_t nonce;
	std::vector<transaction> txs;
	size_t block_size;
	std::string hex_prev;
	std::string hash;

	block_t()
	{
		block_size = sizeof(block_t);
	}

	void add_tx(pqsign::key_pair pair, uint64_t sum, std::string to)
	{
		transaction tx;
		tx.from = pair.b64_public;
		tx.to = to;
		tx.sum = sum;
		tx.signature = pqsign::sign(tx.get_hash(), pair);

		txs.push_back(tx);
		block_size += tx.from.size();
		block_size += tx.to.size();
		block_size += tx.signature.size();
		block_size += sizeof(tx.sum);
	}

	std::string get_hash()
	{
		// build src string: nonce|txs|block_size|hex_prev
		std::string src_string = std::to_string(nonce);
		for (auto& tx : txs)
		{
			src_string.append(tx.from);
			src_string.append(tx.to);
			src_string.append(tx.signature);
		}
		src_string.append(std::to_string(block_size));
		src_string.append(hex_prev);

		std::vector<unsigned char> hash(picosha2::k_digest_size);
		picosha2::hash256(src_string.begin(), src_string.end(), hash.begin(), hash.end());

		std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());
		return hex_str;
	}

	void mine()
	{
		while (true)
		{
			std::string hash = get_hash();
			short sum = 0;
			for (int i = 0; i < 8; i++)
			{
				sum += (hash[i] - '0');
			}
			if (sum == 0)
			{
				this->hash = hash;
				return;
			}
			nonce++;
		}
	}
};