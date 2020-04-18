
#pragma once

#include "esp_system.h"
#include <atomic>
#include <stdexcept>
#include <stdio.h>
#include "cJSON.h"
#include "esp_log.h"

#define ID_len 12 //bytes
#define ecc_pub_len 32
#define ecc_priv_len 32
#define shared_secret_len 16
#define nih "nih"

int rng(void* state, unsigned char* outbytes, size_t len);
void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer);
void json_to_file(cJSON* towrite, const char* path);
void run_wasm();

enum packet_type : unsigned char{
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
};

template <typename T> struct list_elem{
	T element;
	list_elem<T>* next;
	list_elem(){}
	list_elem(T item){
		element = item;
	}
};
template <typename T> struct list{
	std::atomic_flag mutex = ATOMIC_FLAG_INIT;
	list_elem<T>* first = NULL;
	void add(T toadd);
	int count();
	T peek(int index=-1);
	T pop(int index=-1);
	void lock_mutex();
	void unlock_mutex();
};
//I CAN'T FIGURE OUT GENERICS SO THIS BODGE IS NECASSARY:
//CALLER IS RESPONSIBLE FOR LOCKING AND UNLOCKING
template<typename T> void list<T>::add(T toadd){
	if(first==NULL){
		first = new list_elem<T>(toadd);
		return;
	}
	list_elem<T>* cur = first;
	while(cur->next != NULL)cur = cur->next;
	cur->next = new list_elem<T>(toadd);
}
template<typename T> int list<T>::count(){
	if(first == NULL){
		return 0;
	}
	list_elem<T>* cur = first;
	int i = 0;
	for(;cur->next != NULL;i++,cur = cur->next);
	return i+1;
}
template<typename T> T list<T>::peek(int index){
	//if index is -1, peek at end
	if(index==-1)
		index=count();
	//if empty, use this hack to get the default:
	if(first == NULL) {
		throw std::runtime_error("peeking after end of list");
	}
	list_elem<T>* cur = first;
	for(int i = 0; i < index; i++)cur=cur->next;
	T ret = cur->element;
	return ret;
}
template<typename T> T list<T>::pop(int index){
	if(count() == 0)
		throw std::runtime_error("popping after end of list");
	if(index==-1)
		index=count()-1;
	if(index == 0){
		list_elem<T>* todel_first = first;
		first = first->next;
		T ret_first = todel_first->element;
		delete todel_first;
		return ret_first;
	}
	list_elem<T>* cur = first;
	for(int i = 0; i < index-1; i++){
		if(cur->next == NULL) throw std::runtime_error("popping after end of list");
		cur=cur->next;
	}
	list_elem<T>* todel = cur->next;
	T ret = todel->element;
	cur->next = cur->next->next;
	delete todel;
	return ret;
}
template<typename T> void list<T>::lock_mutex(){
	while (mutex.test_and_set(std::memory_order_acquire));
}
template<typename T> void list<T>::unlock_mutex(){
	mutex.clear(std::memory_order_release); 
}