#include "Nihilo.h"

#include "mbedtls/aes.h"

void encrypt(unsigned char* secret, unsigned char* to_encrypt, int to_encrypt_len, unsigned char* encrypted_buf){
	if(to_encrypt_len % aes_block_size != 0)
		throw std::runtime_error("to_encrypt is not a multiple of block size");
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, secret, shared_secret_len * 8);
	unsigned char* init_vector_source = encrypted_buf;
	encrypted_buf += aes_block_size;
	rng(nullptr, init_vector_source, aes_block_size);
	unsigned char init_vector[aes_block_size];
	memcpy(init_vector, init_vector_source, aes_block_size);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, to_encrypt_len, init_vector, to_encrypt, encrypted_buf);
}

void decrypt(unsigned char* secret, unsigned char* to_decrypt, int to_decrypt_len, unsigned char* decrypted_buf){
	if(to_decrypt_len % aes_block_size != 0)
		throw std::runtime_error("to_encrypt is not a multiple of block size");
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, secret, shared_secret_len * 8);
	unsigned char* init_vector = to_decrypt;
	to_decrypt += aes_block_size;
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, to_decrypt_len, init_vector, to_decrypt, decrypted_buf);
}