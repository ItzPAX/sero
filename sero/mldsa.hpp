#pragma once
#include <cstdint>
#include <time.h>
#include <span>
#include <vector>
#include <string>

using byte_vec = std::vector<uint8_t>;
using byte_span = std::span<const uint8_t>;

// Module lattice based digital signature standard
// implemented according to spec: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

// TODO: Implement true random number generator here:
static byte_vec random_k_bits(std::size_t k)
{
	srand(time(0));
	byte_vec rnd;
	for (int i = 0; i < k; i++)
	{
		rnd.push_back(rand() % 256);
	}
	return rnd;
}

struct key_pair
{
	byte_vec public_key;
	byte_vec private_key;
};

class ml_dsa
{
public:
	static constexpr int q = 8380417;

	ml_dsa() = default;
	key_pair key_gen()
	{
		byte_vec seed = random_k_bits(256);
		if (is_zero(seed))
		{
			return key_pair{};
		}
		return key_gen_internal(seed);
	}

	byte_vec sign(byte_vec private_key, byte_span message, byte_span ctx)
	{
		if (ctx.size() > 255)
			return byte_vec();

		byte_vec rnd = random_k_bits(256);
		if (is_zero(rnd))
		{
			return byte_vec();
		}

		byte_vec md;
		md.reserve(1 + 1 + ctx.size() + message.size());

		md.push_back(0x00);
		md.push_back(static_cast<uint8_t>(ctx.size()));

		md.insert(md.end(), ctx.begin(), ctx.end());
		md.insert(md.end(), message.begin(), message.end());

		return sign_internal(private_key, md, rnd);
	}

	bool verify(byte_vec public_key, byte_span message, byte_vec signature, byte_span ctx)
	{
		if (ctx.size() > 255)
			return false;

		byte_vec md;
		md.reserve(1 + 1 + ctx.size() + message.size());

		md.push_back(0x00);
		md.push_back(static_cast<uint8_t>(ctx.size()));

		md.insert(md.end(), ctx.begin(), ctx.end());
		md.insert(md.end(), message.begin(), message.end());

		return verify_internal(public_key, md, signature);
	}

private:
	bool is_zero(byte_vec vec)
	{
		for (auto& b : vec)
		{
			if (b != 0)
				return false;
		}
		return true;
	}

	key_pair key_gen_internal(byte_vec seed)
	{
		return key_pair{};
	}

	byte_vec sign_internal(byte_vec private_key, byte_vec md, byte_vec rnd)
	{
		return byte_vec();
	}

	bool verify_internal(byte_vec public_key, byte_vec md, byte_vec signature)
	{
		return true;
	}
};