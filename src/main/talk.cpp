#include "Nihilo.h"

#include "mbedtls/aes.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

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
int calc_true_packet_size(int bodylen){//Round up to the nearest block size, and add one block
	int blockno = (bodylen + aes_block_size - 1) / aes_block_size;
	return (blockno + 1) * aes_block_size;
}
//run a serve cycle
void serve(){
	//c socket boilerplate(create socket, bind socket, listen on socket, accept connection)
	int listener_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if(listener_no < 0) 
		throw std::runtime_error("could not create socket");
	ESP_LOGI(nih, "Created socket");
	//allow socket reuse:
	int reuse = 1;
	if(setsockopt(listener_no, SOL_SOCKET, SO_REUSEADDR, (void*) &reuse, sizeof(int)) < 0)
		throw std::runtime_error("could reuse");
	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(tcp_port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if(bind(listener_no, (sockaddr*)&addr, sizeof(sockaddr_in)) < 0)
		throw std::runtime_error("could not bind socket");
	ESP_LOGI(nih, "Bound socket");
	listen(listener_no,1);
	ESP_LOGI(nih, "Listening");
	sockaddr_in other_addr;
	socklen_t other_len = sizeof(sockaddr_in);
	int connection_no = accept(listener_no, (sockaddr*) &other_addr, &other_len);
	if(connection_no < 0)
		throw std::runtime_error("could not accept connection");
	ESP_LOGI(nih, "Connected");
	//receive packet:
	packet_header received_header;
	read(connection_no, &received_header, sizeof(packet_header));
	//find destination:
	int dest = -1;
	for(int i = 0; i < machines.count(); i++)
		if(memcmp(machines.peek(i).ecc_pub, received_header.dest_pub, ecc_pub_len)==0){
			dest = i;
			break;
		}
	if(dest != -1){//if destination has been found, receive the rest of the packet. 
		int to_receive = calc_true_packet_size(received_header.contents_length);
		unsigned char* encrypted_body = (unsigned char*)malloc(to_receive);
		ESP_LOGI(nih, "receiving");
		int n = read(connection_no, encrypted_body, to_receive);
		ESP_LOGI(nih, "read");
		unsigned char secret[shared_secret_len];
		machines.peek(dest).derive_shared(received_header.origin_pub, secret);
		if(n == to_receive){//if the correct number of bytes have been read, decrypt packet
			unsigned char* unencrypted_body = (unsigned char*)malloc(to_receive-aes_block_size);
			decrypt(secret, encrypted_body, to_receive-aes_block_size, unencrypted_body);
			if(unencrypted_body[calc_true_packet_size(received_header.contents_length)-aes_block_size-1] == 0){ //prevent buffer overflow
				unsigned char* IDTgt = unencrypted_body;
				char* funcname = (char*)unencrypted_body + ID_len;
				char* onsuccess = (char*)unencrypted_body + ID_len + max_func_len;
				char* onfailure = (char*)unencrypted_body + ID_len + (max_func_len * 2);
				char* param = (char*)unencrypted_body + ID_len + (max_func_len * 3);
				if(memcmp(IDTgt, machines.peek(dest).ID, ID_len) == 0){//ensure that this packet is valid
					sockaddr_in origin_addr;
					socklen_t len = sizeof(origin_addr);
					getpeername(connection_no, (sockaddr*)&origin_addr, &len);
					char origin_ip[20];
					inet_ntop(AF_INET, &(origin_addr.sin_addr), origin_ip, 20);
					bool found = false;
					for(int i = 0; i < machines.count(); i++){
						if(memcmp(machines.peek(i).ecc_pub, received_header.origin_pub, ecc_pub_len) == 0){//machine was already here
							if(strcmp(machines.peek(i).IP, origin_ip) != 0){//machine has updated IP
								Machine m = machines.pop(i);
								strcpy(m.IP, origin_ip);
								machines.add(m);
							}
							found = true;
							break;
						}
					}
					if(!found){//machine was not known before
						char descrip[100];
						char pub_hex[80];
						bytes_to_hex(received_header.origin_pub, ecc_pub_len, pub_hex);
						snprintf(descrip, sizeof(descrip), "%s:%s", origin_ip, pub_hex);
						ESP_LOGI(nih, "Adding machine with descriptor %s", descrip);
						machines.add(Machine(descrip));
					}
					//ESP_LOGI(nih, "received %s(%s), %s, %s", funcname, param, onsuccess, onfailure);
					//catch nullptrs and fuckups:
					if(strlen(funcname) == 0 || strlen(funcname) >= max_func_len) 
						funcname = nullptr;
					if(strlen(onsuccess) == 0 || strlen(onsuccess) >= max_func_len) 
						onsuccess = nullptr;
					if(strlen(onfailure) == 0 || strlen(onfailure) >= max_func_len) 
						onfailure = nullptr;
					if(strlen(param) == 0) 
						param = nullptr;
					queue_copy(received_header.origin_pub, received_header.dest_pub, funcname, param, onsuccess, onfailure);
				}
				else
					ESP_LOGE(nih, "Target ID does not match target pub");
			}
			else
				ESP_LOGE(nih, "Received message does not end with 0");
			delete unencrypted_body;
		}
		else
			ESP_LOGE(nih, "Wrong number of bytes");
		delete encrypted_body;
	}
	else
		ESP_LOGI(nih, "can't find dest");
	shutdown(connection_no, SHUT_RDWR);
	close(connection_no);
	//stop listening for new connections:
	shutdown(listener_no, SHUT_RDWR);
	close(listener_no);
	ESP_LOGI(nih, "Closed");
}
//send call request to another device
void send_call(Machine origin, Machine target, const char* funcname, const char* param, const char* onsuccess, const char* onfailure){
	if((!origin.local) || target.local)
		throw std::runtime_error("origin is not local, or target is local");
	//create header:
	packet_header pheader;
	memcpy(pheader.origin_pub, origin.ecc_pub, ecc_pub_len);
	memcpy(pheader.dest_pub, target.ecc_pub, ecc_pub_len);
	//calc body length:
	pheader.contents_length = ID_len + (max_func_len * 3) + (param==nullptr?0:strlen(param)) + 2;
	//copy body over:
	unsigned char* unencrypted_body = (unsigned char*)malloc(calc_true_packet_size(pheader.contents_length)-aes_block_size);
	memset(unencrypted_body, 0, calc_true_packet_size(pheader.contents_length)-aes_block_size);
	memcpy(unencrypted_body, target.ID, ID_len);
	strncpy((char*)(unencrypted_body + ID_len), funcname, max_func_len-1);
	if(onsuccess != nullptr)
		strncpy((char*)(unencrypted_body + ID_len + max_func_len), onsuccess, max_func_len-1);
	if(onfailure != nullptr)
		strncpy((char*)(unencrypted_body + ID_len + (max_func_len * 2)), onfailure, max_func_len-1);
	if(param != nullptr)
		strcpy((char*)(unencrypted_body + ID_len + (max_func_len * 3)), param);


	char blap[1000];
	bytes_to_hex(unencrypted_body, calc_true_packet_size(pheader.contents_length)-aes_block_size, blap);
	ESP_LOGI(nih, "hex:%s", blap);

	//create socket:
	int connection_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if(connection_no < 0) 
		throw std::runtime_error("could not create socket");
	hostent* target_ent = gethostbyname(target.IP);
	if(target_ent == nullptr)
		throw std::runtime_error("invalid target IP");
	sockaddr_in target_addr;
	memset(&target_addr, 0, sizeof(sockaddr_in));
	target_addr.sin_family = AF_INET;
	memcpy(&target_addr.sin_addr.s_addr, target_ent->h_addr_list[0], target_ent->h_length);
	target_addr.sin_port = htons(tcp_port);
	if(connect(connection_no, (sockaddr*)&target_addr, sizeof(sockaddr_in)) < 0)
		throw std::runtime_error("Failed to connect");
	//find secret:
	unsigned char secret[shared_secret_len];
	origin.derive_shared(target.ecc_pub, secret);
	//encrypt body and write:
	unsigned char* encrypted_body = (unsigned char*)malloc(calc_true_packet_size(pheader.contents_length));
	encrypt(secret, unencrypted_body, calc_true_packet_size(pheader.contents_length)-aes_block_size, encrypted_body);
	write(connection_no, &pheader, sizeof(pheader));
	write(connection_no, encrypted_body, calc_true_packet_size(pheader.contents_length));
	//end
	shutdown(connection_no, SHUT_RDWR);
	close(connection_no);
	//delete target_ent;//seems to be an issue????
	delete unencrypted_body;
	delete encrypted_body;
}