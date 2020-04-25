
#pragma once

#include "esp_system.h"
#include <atomic>
#include <stdexcept>
#include <stdio.h>
#include "cJSON.h"
#include "esp_log.h"

#include "esp_wifi.h"

#define ID_len 12 //bytes
#define ecc_pub_len 32
#define ecc_priv_len 32
#define shared_secret_len 16
#define nih "nih"

int rng(void* state, unsigned char* outbytes, size_t len);
void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer);
void json_to_file(cJSON* towrite, const char* path);
char* run_wasm(char* name, char* param, unsigned char* wasm, unsigned int wasm_length, unsigned char* ID);
void init_flash();
void init_wifi();
ip_event_got_ip_t connect_wifi(const char* ssid, const char* psk);
void register_root(ip_event_got_ip_t ip_info, unsigned char* root_pub);

/*enum packet_type : unsigned char{
	list_machines = 0,
	reply_machines = 1,
	encrypted = 2
};
struct packet_header{
	packet_type type;
	unsigned short len;
};
struct encrypted_header{
	unsigned char source[ecc_pub_len];
	unsigned char dest[ecc_pub_len];
};*/

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