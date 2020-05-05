
#pragma once

#include "esp_system.h"
#include <atomic>
#include <stdexcept>
#include <stdio.h>
#include "cJSON.h"
#include "esp_log.h"
#include <cstring>
#include "esp32/sha.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

#include "esp_wifi.h"

#define ID_len 12 //bytes
#define ecc_pub_len 32
#define ecc_priv_len 32
#define shared_secret_len 16
#define aes_block_size 16
#define tcp_port 7328
#define max_func_len 30
#define nih "nih"

int rng(void* state, unsigned char* outbytes, size_t len);
void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer);
void hex_to_bytes(char* hexbuffer, unsigned char* bytes);
void json_to_file(cJSON* towrite, const char* path);
cJSON* file_to_json(const char* path);
void save_wasm(unsigned char* ID, unsigned char* wasm, int len);
int load_wasm(unsigned char* ID, unsigned char** wasm);

struct packet_header{
	unsigned char origin_pub[ecc_pub_len];
	unsigned char dest_pub[ecc_pub_len];
	uint16_t contents_length; //packet true length = (roundup(contents_length/aes_block_size)+1)*aes_block_size
};

template<typename T> struct list_elem{
	T elem;
	list_elem<T>* next = nullptr;
	list_elem(){}
	list_elem(T el){elem = el;}
};
template<typename T> struct list{
	list(){}
	list_elem<T> minus_one_th;//dummy -1th element to simplify operations
	void add(T toadd){
		list_elem<T>* cur = &minus_one_th;
		while(cur->next != nullptr) cur = cur->next;
		cur->next = new list_elem<T>(toadd);
	}
	int count(){
		list_elem<T>* cur = &minus_one_th;
		int i = 0;
		while(cur->next != nullptr) {
			i++;
			cur = cur->next;
		}
		return i;
	}
	T peek(int index=-1){
		if(index == -1) index += count();
		list_elem<T>* cur = &minus_one_th;
		for(int i = 0; i <= index; i++){
			cur = cur->next;
			if(cur == nullptr) throw std::runtime_error("peeking off the end");
		}
		return cur->elem;
	}
	T pop(int index=-1){
		int cnt = count();
		if(cnt == 0) throw std::runtime_error("popping empty list");
		if(index == -1) index += cnt;
		list_elem<T>* cur = &minus_one_th;
		for(int i = 0; i < index; i++){
			cur = cur->next;
			if(cur == nullptr || cur->next == nullptr) throw std::runtime_error("popping off the end");
		}
		list_elem<T>* l_elem = cur->next;
		cur->next = l_elem->next;
		T ret = l_elem->elem;
		delete l_elem;
		return ret;
	}
	void empty(){
		while(count() > 0)
			pop();
	}
	~ list(){
		empty();
	}
};

template<typename T0, typename T1> struct key_value_pair{
	T0 key;
	T1 value;
	key_value_pair(){}
	key_value_pair(T0 k, T1 v){
		key = k;
		value = v;
	}
};

template<typename T> class locker{
	private:
		T target;
		std::atomic_flag mutex = ATOMIC_FLAG_INIT;
	public:
	T* acquire(){
		while (mutex.test_and_set(std::memory_order_acquire));
		return &target;
	}
	void release(){
		mutex.clear(std::memory_order_release); 
	}
	void set(T toset){
		*acquire() = toset;
		release();
	}
	locker(T toset){
		set(toset);
	}
};

struct Machine{
	unsigned char ID[ID_len];
	char ID_str[(ID_len*2)+1];
	unsigned char ecc_pub[ecc_pub_len];
	unsigned char ecc_priv[ecc_priv_len];
	bool local;
	char IP[20];
	void calc_ID(){
		unsigned char pub_digest[32];
		esp_sha(SHA2_256, ecc_pub, ecc_pub_len, pub_digest);
		memccpy(ID, pub_digest, 1, ID_len);
		bytes_to_hex(ID, ID_len, ID_str);
	}
	Machine(){}
	Machine(char* description){
		char* ip = description;
		char* pub_hex = nullptr;
		for(int i = 0; i < strlen(description); i++)
			if(description[i] == ':'){
				description[i] = '\0';
				pub_hex = description + i + 1;
			}
		if(strlen(pub_hex) != ecc_pub_len*2)
			throw std::runtime_error("wrong length pub");
		hex_to_bytes(pub_hex, ecc_pub);
		strcpy(IP, ip);
		calc_ID();
		local = false;
	}
	Machine(mbedtls_ecp_group* grp, mbedtls_ecp_point* pub){
		if(mbedtls_mpi_write_binary(&pub->X, ecc_pub, ecc_pub_len) != 0)
			throw std::runtime_error("wrong number of bytes written to buffer");
		memset(IP, 0, sizeof(IP));
		calc_ID();
		local = false;
	}
	Machine(mbedtls_ecp_group* grp, mbedtls_ecp_point* pub, mbedtls_mpi* priv) : Machine(grp, pub){
		mbedtls_mpi_write_binary(priv, ecc_priv, ecc_priv_len);
		memset(IP, 0, sizeof(IP));
		local = true;
	}
	Machine(cJSON* description){
		hex_to_bytes(cJSON_GetObjectItemCaseSensitive(description, "Pub")->valuestring, ecc_pub);
		hex_to_bytes(cJSON_GetObjectItemCaseSensitive(description, "Priv")->valuestring, ecc_priv);
		memset(IP, 0, sizeof(IP));
		calc_ID();
		local = true;
	}
	void derive_shared(unsigned char* other_pub, unsigned char* secret_buf){//derive the shared secret of this machine(pub/priv) and another machine(pub)
		if(!local) throw std::runtime_error("derive_shared must be called against local machine");
		//create/load context:
		mbedtls_ecdh_context ecc_ctxt;
		mbedtls_ecdh_init(&ecc_ctxt);
		mbedtls_ecp_group_load(&ecc_ctxt.grp, MBEDTLS_ECP_DP_CURVE25519);
		//write pub:
		mbedtls_mpi_lset(&ecc_ctxt.Qp.Z, 1);
		mbedtls_mpi_read_binary(&ecc_ctxt.Qp.X, other_pub, ecc_pub_len);
		//write priv:
		mbedtls_mpi_read_binary(&ecc_ctxt.d, ecc_priv, ecc_priv_len);
		//create secret:
		mbedtls_ecdh_compute_shared(&ecc_ctxt.grp, &ecc_ctxt.z, &ecc_ctxt.Qp, &ecc_ctxt.d, rng, NULL);
		if(mbedtls_mpi_size(&ecc_ctxt.z) < shared_secret_len) throw std::runtime_error("secret too small");
		//write into secret_buf
		unsigned char intermediate_secret_buf[32];
		mbedtls_mpi_write_binary(&ecc_ctxt.z, intermediate_secret_buf, 32);
		memcpy(secret_buf, intermediate_secret_buf, shared_secret_len);
		//cleanup
		mbedtls_ecdh_free(&ecc_ctxt);
	}
};

extern list<Machine> machines;

char* run_wasm(char* name, char* param, unsigned char* ID);
void init_flash();
void init_wifi();
ip_event_got_ip_t connect_wifi(const char* ssid, const char* psk);
void register_machine(ip_event_got_ip_t ip_info, char* root_pub_hex);
void load_non_local(ip_event_got_ip_t ip_info, list<Machine>* list);
Machine load_from_memory(char* id_str);
void exec(unsigned char* origin_pub, unsigned char* dest_pub, char* funcname, char* param, char* onsuccess, char* onfailure);
void encrypt(unsigned char* secret, unsigned char* to_encrypt, int to_encrypt_len, unsigned char* encrypted_buf);
void decrypt(unsigned char* secret, unsigned char* to_decrypt, int to_decrypt_len, unsigned char* decrypted_buf);
void serve();
void send_call(Machine origin, Machine target, const char* funcname, const char* param, const char* onsuccess, const char* onfailure);
void queue_task(unsigned char* origin_pub, unsigned char* dest_pub, char* funcname, char* param, char* onsuccess, char* onfailure);
void queue_copy(unsigned char* origin_pub, unsigned char* dest_pub, char* funcname, char* param, char* onsuccess, char* onfailure);
void empty_queue();