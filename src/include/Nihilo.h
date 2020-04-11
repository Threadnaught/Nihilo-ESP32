
#pragma once

#include "esp_system.h"
#include <atomic>
#include <stdexcept>

#define ID_len 12 //bytes
#define ecc_pub_len 32
#define ecc_priv_len 32
#define shared_secret_len 16
#define nih "nih"

template <typename T> struct ListElem{
	T element;
	ListElem<T>* next;
	ListElem(){}
	ListElem(T item){
		element = item;
	}
};

int rng(void* state, unsigned char* outbytes, size_t len);
void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer);

template <typename T> struct List{
	std::atomic_flag mutex = ATOMIC_FLAG_INIT;
	ListElem<T>* first = NULL;
	void add(T toadd);
	int count();
	T peek(int index=-1);
	T pop(int index=-1);
	void lock_mutex();
	void unlock_mutex();
};
//I CAN'T FIGURE OUT GENERICS SO THIS BODGE IS NECASSARY:
template<typename T> void List<T>::add(T toadd){
	lock_mutex();
	if(first==NULL){
		first = new ListElem<T>(toadd);
		unlock_mutex();
		return;
	}
	ListElem<T>* cur = first;
	while(cur->next != NULL)cur = cur->next;
	cur->next = new ListElem<T>(toadd);
	unlock_mutex();
}
template<typename T> int List<T>::count(){
	lock_mutex();
	if(first == NULL){
		unlock_mutex();
		return 0;
	}
	ListElem<T>* cur = first;
	int i = 0;
	for(;cur->next != NULL;i++,cur = cur->next);
	unlock_mutex();
	return i+1;
}
template<typename T> T List<T>::peek(int index){
	lock_mutex();
	//if index is -1, peek at end
	if(index==-1)
		index=count();
	//if empty, use this hack to get the default:
	if(first == NULL) {
		unlock_mutex();
		throw std::runtime_error("peeking after end of list");
	}
	ListElem<T>* cur = first;
	for(int i = 0; i < index; i++)cur=cur->next;
	T ret = cur->element;
	unlock_mutex();
	return ret;
}
template<typename T> T List<T>::pop(int index){
	lock_mutex();
	if(count() == 0)
		throw std::runtime_error("popping after end of list");
	if(index==-1)
		index=count()-1;
	if(index == 0){
		ListElem<T>* todel_first = first;
		first = first->next;
		T ret_first = todel_first->element;
		delete todel_first;
		unlock_mutex();
		return ret_first;
	}
	ListElem<T>* cur = first;
	for(int i = 0; i < index-1; i++){
		if(cur->next == NULL) throw std::runtime_error("popping after end of list");
		cur=cur->next;
	}
	ListElem<T>* todel = cur->next;
	T ret = todel->element;
	cur->next = cur->next->next;
	delete todel;
	unlock_mutex();
	return ret;
}
template<typename T> void List<T>::lock_mutex(){
	while (mutex.test_and_set(std::memory_order_acquire));
}
template<typename T> void List<T>::unlock_mutex(){
	mutex.clear(std::memory_order_release); 
}