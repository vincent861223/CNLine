#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>
//#include <pthread.h>

#define MAX_BUF 4096
#define CLT_MAX_BUF 1024
#define MAX_STR 256
#define TIMEOUT 250
#define MAX_QUEUE 10
#define MAX_CLIENTS 1024

struct sockaddr_in server_info;
unsigned int addrlen;

typedef struct _Client{
    struct sockaddr_in client_info;
    int fd;
    char addr[MAX_STR];
    int port_num;
    char rcvBuf[MAX_BUF];
}Client;

typedef struct _Server{
    struct sockaddr_in server_info;
    char addr[MAX_STR];
    int port_num;
    int listen_fd;
	fd_set listenSet;
	fd_set clientSet;
}Server;

Client clients[MAX_CLIENTS];
Server server;

// ------ Forward Declaration------ //
void usage();
int createSocket();
void initServer(Server* server, int port_num);
void bind_listen(Server* server);
void acceptClient();
int listenFdReady();
int clientFdReadReady();
int parseCommand(char* message, char* option);
int registration(char* option);
int login(char* option, int readyfd);
int add(char* option);
int chat(char* option, int readyfd);
int sendMessage(char* option);
int readMessage(char* option, int readyfd);
int sendFile(char* option, int readyfd);
int readFile(char* option, int readyfd);
void encode(char* str);
void decode(char* str);
// -------------------------------- //

int main(int argc, char* argv[]){
    if(argc != 2) usage();
    addrlen = sizeof(server.server_info);
    int port_num = atoi(argv[1]), rcv_size = 0;
    char* option = NULL;
    initServer(&server, port_num);
    bind_listen(&server);
    printf("server listening at port: %d, listenfd: %d\n", server.port_num, server.listen_fd);
    while(1){
	int readyfd = 0;
	if((readyfd = clientFdReadReady())){
	    rcv_size = recv(readyfd, clients[readyfd].rcvBuf, MAX_BUF, 0);
		if(rcv_size == 0){
		   	printf("client with address: %s:%d disconnected at fd %d\n", clients[readyfd].addr, clients[readyfd].port_num, clients[readyfd].fd);
		    FD_CLR(readyfd, &server.clientSet);
		    close(readyfd);
		}else{   
		    printf("client ready at fd %d, received message: %s\n", readyfd, clients[readyfd].rcvBuf);
		    int cmd = parseCommand(clients[readyfd].rcvBuf, option);
		    switch(cmd){
		    	case 1: 
		    		printf("command: register\n");
		    		//printf("option: %s\n", option);
		    		registration(option);
		    		break;
		    	case 2: 
		    		printf("command: send\n"); 
		    		//printf("option: %s\n", option);
		    		sendMessage(option);
		    		break;
		    	case 3: 
		    		printf("command: read\n"); 
		    		//printf("option: %s\n", option);
		    		readMessage(option, readyfd);
		    		break;
		    	case 4: 
		    		printf("command: sendFile\n"); 
		    		//printf("option: %s\n", option);
		    		sendFile(option, readyfd);
		    		//readMessage(option, readyfd);
		    		break;
		    	case 5:
		    		printf("command: readFile\n"); 
		    		readFile(option, readyfd);
		    		break;
		    	case 6:
		    		printf("command: login\n"); 
					login(option,readyfd);
					break;
				case 7:
					printf("command: add\n");
					add(option);
					break;
				case 8:
					printf("command: chat\n");
					chat(option, readyfd);
					break;
		    	case -1: 
		    		printf("command: error\n"); 
		    		break;
		    }
		    memset(&clients[readyfd].rcvBuf, 0, MAX_BUF);
		}
	}else if(listenFdReady()){
		acceptClient();
	}
    }
    return 0;
}

void usage(){
    printf("[usage]: ./server <listen_port>");
    exit(-1);
}


int createSocket(){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1){
    	printf("Failed to create socket\n");
    	exit(-1);	
    }
    return fd;
}

void initServer(Server* server, int port_num){
    bzero((void*)&server->server_info, addrlen);
    server->server_info.sin_family = PF_INET;
    server->server_info.sin_addr.s_addr = INADDR_ANY;
    server->server_info.sin_port = htons(port_num);
    server->listen_fd = createSocket();
    server->port_num = port_num;
    FD_ZERO(&server->listenSet);
    FD_ZERO(&server->clientSet);
    FD_SET(server->listen_fd, &server->listenSet);
}

void bind_listen(Server* server){
    int ret = bind(server->listen_fd,(struct sockaddr*) &(server->server_info), addrlen);
    if(ret < 0){
	perror("Failed to bind socket:");
	exit(-1);
    }
    ret = listen(server->listen_fd, MAX_QUEUE);
    if(ret < 0){
	perror("Failed to listen:");
	exit(-1);
    }
}

void acceptClient(){
    //char hello[] = "Hello. Welcome to CNLine!!!\n";
    struct sockaddr_in tmp_client_info;
	int newfd = accept(server.listen_fd, (struct sockaddr*) &tmp_client_info, &addrlen);
	memcpy(&clients[newfd].client_info, &tmp_client_info, addrlen);
	clients[newfd].fd = newfd;
	inet_ntop(AF_INET, &clients[newfd].client_info.sin_addr, clients[newfd].addr, INET_ADDRSTRLEN);
	clients[newfd].port_num = clients[newfd].client_info.sin_port;
	FD_SET(newfd, &server.clientSet);
	//->printf("client with address: %s:%d connected at fd %d\n", clients[newfd].addr, clients[newfd].port_num, clients[newfd].fd);	
	printf("client with address: %s:%d connected at fd %d\n", clients[newfd].addr, clients[newfd].port_num, newfd);
	//send(clients[newfd].fd, hello, sizeof(hello), 0);
}

int listenFdReady(){
	fd_set listenSet;
	memcpy(&listenSet, &server.listenSet, sizeof(listenSet));
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 50;
	int ret = select(server.listen_fd+1, &listenSet, NULL, NULL, &timeout);
	if (ret < 0) { 
		perror("listen_fd select error:");
		exit(-1);
	}else {
		return ret;
	}
}

int clientFdReadReady(){
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 500;
	fd_set clientSet;
	memcpy(&clientSet, &server.clientSet, sizeof(clientSet));
	int ret = select(MAX_CLIENTS, &clientSet, NULL, NULL, &timeout);
	if(ret < 0){
		perror("clientFd select error:");
		exit(-1);
	}else if(ret == 0){
		return ret;
	}else{
		for(int i = 0; i < MAX_CLIENTS; i++){
			if (FD_ISSET(i, &clientSet)) return i;
		}
	}
	return 0;
}

int parseCommand(char* message, char* option){
	int cmd = -1;
    char* ptr = strtok(message, ":");
    if(ptr == NULL) return cmd;
    if(strcmp(ptr, "register") == 0) cmd = 1;
    else if(strcmp(ptr, "send") == 0) cmd = 2;
    else if(strcmp(ptr, "read") == 0) cmd = 3;
    else if(strcmp(ptr, "sendFile") == 0) cmd = 4;
    else if(strcmp(ptr, "readFile") == 0) cmd = 5;
    else if(strcmp(ptr, "login") == 0) cmd = 6;
	else if(strcmp(ptr, "add") == 0) cmd = 7;
	else if(strcmp(ptr, "chat") == 0) cmd = 8;
    option = ptr + strlen(ptr) + 1;
    return cmd;
}

int login(char* option, int readyfd){

	char* username, *password;
	char* member_file_name = "member.txt";
	char* ptr = strtok(option, " ");
	int u = 0, p = 0;
	
	while(ptr != NULL){

		if(strcmp(ptr, " ") == 0) continue;
		
		if(u) username = ptr;
		else if(p) password = ptr;
		
		u = (strcmp(ptr, "name") == 0);
		p = (strcmp(ptr, "pwd") == 0);
		
		if(p) ptr = strtok(NULL, "\0");
		else ptr = strtok(NULL, " ");
	}

	FILE* member_file = fopen(member_file_name, "r");
	char buf[MAX_BUF];
	int line_cnt = 0;

	printf("%s\n",username);
	printf("%s\n",password);
	if(member_file == NULL) member_file = fopen(member_file_name, "w");


	while(fgets(buf, MAX_BUF, member_file)){
		
		char* token = strtok(buf, ",");

		if(strcmp(username,token) == 0){
			
			printf("existing user %s\n",token);
			
			token = strtok(NULL,"\n");
			printf("%s\n",token);
			
			if(strcmp(password,token) == 0){

				printf("password correct\n");
				fclose(member_file);
				send(readyfd, "1", strlen("1"), 0);
				

				return 1;
			}
			else{
				printf("password incorrect\n");
				fclose(member_file);
				send(readyfd, "2", strlen("2"), 0);
				return 0;
			}
		}
		line_cnt++;
	}
	fclose(member_file);
	printf("not existing this user\n");
	send(readyfd, "0", strlen("0"), 0);
	return 0;
}

int registration(char* option){

	char* username, *password;
	char* member_file_name = "member.txt";
	char* ptr = strtok(option, " ");
	int u = 0, p = 0;
	
	while(ptr != NULL){

		if(strcmp(ptr, " ") == 0) continue;
		
		if(u) username = ptr;
		else if(p) password = ptr;
		
		u = (strcmp(ptr, "name") == 0);
		p = (strcmp(ptr, "pwd") == 0);
		
		if(p) ptr = strtok(NULL, "\n");
		else ptr = strtok(NULL, " ");
	}
	
	FILE* member_file = fopen(member_file_name, "a");
	fprintf(member_file, "%s,%s\n", username, password);
	fclose(member_file);

	char* dir = "Relation";
	char file_path[MAX_BUF];
	sprintf(file_path, "%s/%s.txt", dir, username);
	struct stat st = {0};
	if(stat(dir, &st) == -1) mkdir(dir, 0700);

	FILE* friend_file = fopen(file_path, "a");
	fclose(friend_file);
	//printf("%s\n",username);
	//printf("%s\n",password);

	return 0;
}

int add(char* option){

	char* username, *friend;
	char* ptr = strtok(option, " ");
	int u = 0, f = 0;
	
	while(ptr != NULL){

		if(strcmp(ptr, " ") == 0) continue;
		
		if(u) username = ptr;
		else if(f) friend = ptr;
		
		u = (strcmp(ptr, "name") == 0);
		f = (strcmp(ptr, "friend") == 0);
		
		if(f) ptr = strtok(NULL, "\r\n");
		else ptr = strtok(NULL, " ");
	}

	printf("%s\n",username);
	printf("%s\n",friend);

	FILE* member_file = fopen("member.txt", "r");
	char buf[MAX_BUF];
	int registered = 0;
	


	while(fgets(buf, MAX_BUF, member_file)){
		
		char* token = strtok(buf, ",");

		if(strcmp(friend,token) == 0){
			printf("This friend has registered\n");
			registered = 1;
			break;
			
		}
		
	}
	fclose(member_file);


	if(registered){

		char* dir = "Relation";
		char file_path[MAX_BUF];
		sprintf(file_path, "%s/%s.txt", dir, username);
		struct stat st = {0};
		if(stat(dir, &st) == -1) mkdir(dir, 0700);
		
		FILE* friend_file = fopen(file_path, "a");
		fprintf(friend_file, "%s\n", friend);
		fclose(friend_file);



	}

	
	
	return 0;

}

int chat(char* option, int readyfd){

	char* username, *friend;
	char* ptr = strtok(option, " ");
	int u = 0, f = 0;
	
	while(ptr != NULL){

		if(strcmp(ptr, " ") == 0) continue;
		
		if(u) username = ptr;
		else if(f) friend = ptr;
		
		u = (strcmp(ptr, "name") == 0);
		f = (strcmp(ptr, "friend") == 0);
		
		if(f) ptr = strtok(NULL, "\r\n");
		else ptr = strtok(NULL, " ");
	}

	printf("%s\n",username);
	printf("%s\n",friend);
	
	char file_path[MAX_BUF];
	char buf[MAX_BUF];
	int toward = 0;

	FILE* member_file = fopen("member.txt", "r");
	int registered = 0;
	
	while(fgets(buf, MAX_BUF, member_file)){
		
		char* token = strtok(buf, ",");

		if(strcmp(friend,token) == 0){
			printf("This friend has registered\n");
			registered = 1;
			break;
			
		}
		
	}
	fclose(member_file);

	if(registered == 0){
		printf("This friend hasn't registered\n");
		send(readyfd, "3", strlen("3"), 0);
		return 0;
	}
	

	sprintf(file_path,"./Relation/%s.txt",username);
	FILE* user_file = fopen(file_path, "r");
	int line_cnt = 0;
	

	while(fgets(buf, MAX_BUF, user_file)){

		char* token = strtok(buf, "\r\n");
		printf("%s\n",token);

		
		if(strcmp(token,friend) == 0){
			toward = 1;
			break;
		}
		line_cnt++;
		
		
	}
	fclose(user_file);

	if(toward == 0){
		printf("You hasn't added %s as your friend\n",friend);
		send(readyfd, "0", strlen("0"), 0);
		return 0;
	}
	
	int backward = 0;
	sprintf(file_path,"./Relation/%s.txt",friend);
	FILE* friend_file = fopen(file_path, "r");

	
	while(fgets(buf, MAX_BUF, friend_file)){

		char* token = strtok(buf, "\r\n");
		printf("%s\n",token);

		if(strcmp(token,username) == 0){
			backward = 1;
			break;
		}
		
	}
	fclose(friend_file);
	
	
	if(toward == 1 && backward == 0){
		printf("%s hasn't added you as his friend\n",friend);
		send(readyfd, "2", strlen("2"), 0);
	}
	else if(toward == 1 && backward == 1){
		printf("friendship\n");
		send(readyfd, "1", strlen("1"), 0);
	}
	
	
	return 0;
}

int sendMessage(char* option){

	char* from_name = NULL, *to_name = NULL, *msg = NULL, *ptr = strtok(option, " ");
	char msg_file_path[MAX_STR], usr_dir_name[MAX_STR];

	char codename[MAX_STR];
    char codemsg[MAX_STR];

	int f = 0, t = 0, m = 0;
	while(ptr != NULL){
		if(strcmp(ptr, " ") == 0) continue;
		//printf("token: %s\n", ptr);
		if(f) from_name = ptr;
		else if(t) to_name = ptr;
		else if(m) msg = ptr;
		f = (strcmp(ptr, "from") == 0);
		t = (strcmp(ptr, "to") == 0);
		m = (strcmp(ptr, "msg") == 0);
		if(m) ptr = strtok(NULL, "\n");
		else ptr = strtok(NULL, " ");
	}
	if(from_name == NULL || to_name == NULL || msg == NULL) return -1;
	//printf("from_name:%s\n", from_name);
	//printf("to_name:%s\n", to_name);
	//printf("msg:%s\n", msg);
	int sort = strcmp(from_name, to_name);
	sprintf(usr_dir_name, "%s_%s", sort < 0?from_name:to_name, sort < 0?to_name:from_name);
	sprintf(msg_file_path, "%s/%s.txt", usr_dir_name, usr_dir_name);
	struct stat st = {0};
	if(stat(usr_dir_name, &st) == -1) mkdir(usr_dir_name, 0700);
	FILE* msg_file = fopen(msg_file_path, "a");

	strcpy(codename,from_name);
	strcpy(codemsg,msg);
	encode(codename);
	encode(codemsg);

	//fprintf(msg_file, "%s:%s\n", from_name, msg);
	fprintf(msg_file, "%s:%s\n", codename, codemsg);
	fclose(msg_file);
	return 0;
}

int readMessage(char* option, int readyfd){
	char *usr1_name = NULL, *usr2_name = NULL, *ptr = strtok(option, " ");
	int line_num = -1;
	char usr_dir_path[MAX_STR], msg_file_name[2*MAX_STR+64];
	
	char uncodemsg[MAX_STR];

	int arg_cnt = 0;
	while(ptr != NULL){
		if(strcmp(ptr, " ") == 0) {ptr = strtok(NULL, " \r\n"); continue;}
		if (arg_cnt == 0) usr1_name = ptr;
		else if(arg_cnt == 1) usr2_name = ptr;
		else if(arg_cnt == 2) line_num = atoi(ptr);
		arg_cnt++;
		ptr = strtok(NULL, " \r\n\0");
	}
	if(arg_cnt < 3) {
		char ack[] = "ack";
		send(readyfd, ack, strlen(ack), 0);
		return -1;
	}
	// printf("usr1_name:%s\n", usr1_name);
	// printf("usr2_name:%s\n", usr2_name);
	// printf("line_num:%d\n", line_num);
	//if(line_num < 0) return -1;
	int sort = strcmp(usr1_name, usr2_name);
	sprintf(usr_dir_path, "%s_%s", sort < 0?usr1_name:usr2_name, sort < 0?usr2_name:usr1_name);
	sprintf(msg_file_name, "%s/%s.txt", usr_dir_path, usr_dir_path);
	struct stat st = {0};
	if(stat(usr_dir_path, &st) == -1) mkdir(usr_dir_path, 0700);
	FILE* msg_file = fopen(msg_file_name, "r");
	if(msg_file == NULL){
		msg_file = fopen(msg_file_name, "w");
		fclose(msg_file);
		char ack[] = "ack";
		send(readyfd, ack, strlen(ack), 0);
		return 0;
	}
	char file_buf[MAX_BUF];
	int line_cnt = 0, sent = 0;
	while(fgets(file_buf, MAX_BUF, msg_file)){

		strcpy(uncodemsg,file_buf);
		decode(uncodemsg);

		if(line_cnt >= line_num){
			//send(readyfd, file_buf, strlen(file_buf), 0);
			send(readyfd, uncodemsg, strlen(uncodemsg), 0);
			sent = 1;
		}
		line_cnt++;
	}
	if(!sent){
		char ack[] = "ack";
		send(readyfd, ack, strlen(ack), 0);
	}
	fclose(msg_file);
	return 0;
}

int sendFile(char* option, int readyfd){
	char* from_name = NULL, *to_name = NULL, *filename = NULL, *msg = NULL, *ptr = strtok(option, " ");
	char usr_dir_name[2*MAX_STR+64], file_path[3*MAX_STR+64];
	int f = 0, t = 0, fn = 0, s = 0, m = 0, size = 0;
	while(ptr != NULL){
		if(strcmp(ptr, " ") == 0) continue;
		//printf("token: %s\n", ptr);
		if(f) from_name = ptr;
		else if(t) to_name = ptr;
		else if(fn) filename = ptr;
		else if(s) size = atoi(ptr);
		f = (strcmp(ptr, "from") == 0);
		t = (strcmp(ptr, "to") == 0);
		fn = (strcmp(ptr, "filename") == 0);
		s = (strcmp(ptr, "size") == 0);
		m = (strcmp(ptr, "msg") == 0);
		if(m){
			msg = ptr + 4;
			break;
		}
		ptr = strtok(NULL, " ");
	}
	printf("size:%d\n", size);
	int sort = strcmp(from_name, to_name);
	sprintf(usr_dir_name, "%s_%s", sort < 0?from_name:to_name, sort < 0?to_name:from_name);
	sprintf(file_path, "%s/%s", usr_dir_name, filename);
	struct stat st = {0};
	if(stat(usr_dir_name, &st) == -1) mkdir(usr_dir_name, 0700);
	FILE* transfer_file = fopen(file_path, "ab");
	fwrite(msg, 1, size, transfer_file);
	fclose(transfer_file);
	char ack[] = "ack";
	send(readyfd, ack, strlen(ack), 0);
	return 0;
}

int readFile(char* option, int readyfd){
	char* from_name = NULL, *to_name = NULL, *filename = NULL;
	char transfer_file_path[MAX_STR], usr_dir_name[MAX_STR], sendMsg[CLT_MAX_BUF];
	int f = 0, t = 0, fn = 0;
	char* ptr = strtok(option, " ");
	while(ptr != NULL){
		if(strcmp(ptr, " ") == 0) continue;
		if(f) from_name = ptr;
		else if(t) to_name = ptr;
		else if(fn) filename = ptr;
		f = (strcmp(ptr, "from") == 0);
		t = (strcmp(ptr, "to") == 0);
		fn = (strcmp(ptr, "filename") == 0);
		if(fn) ptr = strtok(NULL, "\0");
		else ptr = strtok(NULL, " ");
	}
	//printf("from_name:%s\n", from_name);
	//printf("to_name:%s\n", to_name);
	//printf("filename:%s\n", filename);
	//printf("msg:%s\n", msg);
	int sort = strcmp(from_name, to_name);
	sprintf(usr_dir_name, "%s_%s", sort < 0?from_name:to_name, sort < 0?to_name:from_name);
	if(strncmp(filename, "NULL", 4) == 0){ 
		//read file list in directory, and send the file list to usr.
		DIR *d;
		struct dirent *dir;
		d = opendir(usr_dir_name);
		if (d) {
			while ((dir = readdir(d)) != NULL){
				if(strncmp(dir->d_name, ".", 1) == 0 || strncmp(dir->d_name, usr_dir_name, strlen(usr_dir_name)) == 0 ) continue;
				sprintf(sendMsg, "%s\n", dir->d_name);
				send(readyfd, sendMsg, strlen(sendMsg), 0);
			}
			closedir(d);
		}
	}
	else{
		sprintf(transfer_file_path, "%s/%s", usr_dir_name, filename);
		//printf("transfer_file_path: %s\n", transfer_file_path);
		FILE* transfer_file = fopen(transfer_file_path, "rb");
		if(transfer_file == NULL){
			sprintf(sendMsg, "file not exit!\n");
			send(readyfd, sendMsg, strlen(sendMsg), 0);
			return -1;
		}
		char file_buf[CLT_MAX_BUF - MAX_STR - 64];
		int read_len = 0;
		while((read_len = fread(file_buf, 1, CLT_MAX_BUF - MAX_STR - 64, transfer_file)) != 0){
			struct timeval tv = {0, 7000};
			sprintf(sendMsg, "sendFile %s %d:", filename, read_len);
			int msg_size = strlen(sendMsg);
			char* cptr = &sendMsg[msg_size];
			for(int i = 0; i < read_len; i++, cptr++) *cptr = file_buf[i];
			select(readyfd+1, NULL, NULL, NULL, &tv);
            send(readyfd, sendMsg, msg_size + read_len, 0);
            memset(file_buf, 0, CLT_MAX_BUF - MAX_STR - 64);
            memset(sendMsg, 0, CLT_MAX_BUF);
            while(recv(readyfd, clients[readyfd].rcvBuf, MAX_BUF, 0) == 0);
		}
		sprintf(sendMsg, "sendFile %s %d:", filename, -1);
		send(readyfd, sendMsg, strlen(sendMsg), 0);

		fclose(transfer_file);
		return 0;
	}
	return 0;
}


void encode(char* str){
    char c;
    int i;
    int n=5;

    for(i=0;i<strlen(str);++i){ 
        c=str[i];
        if(c>='a' && c<='z'){ 
            if(c+n%26<='z'){  
                str[i]=(char)(c+n%26); 
            }else{  
                str[i]=(char)(c+n%26-26);
            }
        }else if(c>='A' && c<='Z'){ 
            if(c + n%26 <= 'Z'){  
                str[i]=(char)(c+n%26);
            }else{  
                str[i]=(char)(c+n%26-26);
            }
        }else if(c=='\n'||c==':'){ 
            str[i]=c;
        }
         else if(c>='['&&c<='`')
       {
          if(c+n%6<='`'){  
                str[i]=(char)(c+n%6); 
            }else{  
                str[i]=(char)(c+n%6-6);
            } 
        }
       else if(c>='{'&&c<='~')
       {
            if(c+n%4<='~'){  
                str[i]=(char)(c+n%4); 
            }else{  
                str[i]=(char)(c+n%4-4);
            }
  
        }
         else
          {
            str[i]=(char)(c+n%26-26);
           }
    }
   
}

void decode(char* str){
    char c;
    int i;
    int n=5;

    for(i=0;i<strlen(str);++i){
        c=str[i];
  
        if(c>='a' && c<='z'){
         
            if(c-n%26>='a'){
                str[i]=(char)(c-n%26);
            }else{
               
                str[i]=(char)(c-n%26+26);
            }
        }else if(c >= 'A' && c<='Z'){  
            if(c-n%26>='A'){ 
                str[i]=(char)(c-n%26);
            }else{  
                str[i]=(char)(c-n%26+26);
            }
        }else if(c=='\n'||c==':'){ 
            str[i]=c;
        }
          else if(c>='['&&c<='`')
       {
           if(c-n%6>='['){  
                str[i]=(char)(c-n%6); 
            }else{  
                str[i]=(char)(c-n%6+6);
            }
        }
       else if(c>='{'&&c<='~')
       {
            if(c-n%4>='{'){  
                str[i]=(char)(c-n%4); 
            }else{  
                str[i]=(char)(c-n%4+4);
            }
  
        }
         else
          {
             str[i]=(char)(c-n%26+26);
           }
    }
}


