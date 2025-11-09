#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include <oqs/oqs.h>
#pragma comment(lib, "liboqs/lib/oqs.lib")

#include "base64.h"

namespace pqsign
{
	struct key_pair
	{
		uint8_t* secret_key;
		uint8_t* public_key;
		OQS_SIG* sig;

		std::string b64_secret;
		std::string b64_public;
	};

	__forceinline uint8_t* str_to_u8(const std::string& str)
	{
		uint8_t* buffer = new uint8_t[str.size()];
		std::memcpy(buffer, str.data(), str.size());
		return buffer;
	}

	__forceinline std::string u8_to_str(const uint8_t* data, size_t length)
	{
		return std::string(reinterpret_cast<const char*>(data), length);
	}

	// generates a ml-dsa44 keypair
	__forceinline key_pair generate_key_pair()
	{
		OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
		if (sig == NULL)
		{
			printf("OQS_SIG_alg_ml_dsa_44 was not enabled at compile-time.\n");
			return {};
		}

		uint8_t* public_key = (uint8_t*)malloc(sig->length_public_key);
		uint8_t* secret_key = (uint8_t*)malloc(sig->length_secret_key);

		if (!public_key || !secret_key)
		{
			OQS_MEM_secure_free(secret_key, sig->length_secret_key);
			OQS_MEM_insecure_free(public_key);
			OQS_SIG_free(sig);
			return {};
		}

		if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS)
		{
			fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
			OQS_MEM_secure_free(secret_key, sig->length_secret_key);
			OQS_MEM_insecure_free(public_key);
			OQS_SIG_free(sig);
			return {};
		}

		key_pair pair;
		pair.sig = sig;
		pair.public_key = public_key;
		pair.secret_key = secret_key;

		pair.b64_public = macaron::Base64::Encode(pqsign::u8_to_str(pair.public_key, pair.sig->length_public_key));
		pair.b64_secret = macaron::Base64::Encode(pqsign::u8_to_str(pair.secret_key, pair.sig->length_secret_key));

		return pair;
	}

	// sign a message with the ml-dsa44 algorithm
	__forceinline std::string sign(std::string message, key_pair key)
	{
		uint8_t* signature_u8 = (uint8_t*)malloc(key.sig->length_signature);
		uint8_t* message_u8 = str_to_u8(message);

		if (signature_u8 == NULL)
		{
			fprintf(stderr, "ERROR: malloc failed!\n");
			OQS_MEM_insecure_free(signature_u8);
			return std::string();
		}

		size_t signature_len;
		if (OQS_SIG_sign(key.sig, signature_u8, &signature_len, message_u8, message.size(), key.secret_key) != OQS_SUCCESS)
		{
			fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
			OQS_MEM_insecure_free(message_u8);
			return std::string();
		}

		std::string signature = u8_to_str(signature_u8, signature_len);
		std::string b64_signature = macaron::Base64::Encode(signature);

		return b64_signature;
	}

	// verify a signature is valid
	__forceinline bool verify(std::string message, std::string b64_signature, key_pair key)
	{
		uint8_t* message_u8 = str_to_u8(message);
		std::string signature; macaron::Base64::Decode(b64_signature, signature);
		uint8_t* signature_u8 = str_to_u8(signature);

		if (OQS_SIG_verify(key.sig, message_u8, message.size(), signature_u8, signature.size(), key.public_key) != OQS_SUCCESS)
		{
			fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
			OQS_MEM_insecure_free(message_u8);
			OQS_MEM_insecure_free(signature_u8);
			return false;
		}

		return true;
	}
}