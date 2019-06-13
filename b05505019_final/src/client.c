#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_BUF 1024
#define MAX_STR 256
#define TIMEOUT 250

typedef struct{
    int connect_fd;
    char ip[MAX_STR];
    char port[MAX_STR];
    struct sockaddr_in connection_info;
}Server;

typedef struct{
    Server* server;
    char* usr_name;
    char* chat_usr;
}Thread_data;

Server server;
unsigned int addrlen;
char usr_name[MAX_STR];
char chat_usr[MAX_STR];
char chat_cand[MAX_STR];
char option[MAX_STR];
char pwd[MAX_BUF];
int server_ok = 1, line_cnt = 0, rcv_total_cnt = 0, read_req_ok = 1, wait_chat = 0;
pthread_mutex_t server_ok_lock = PTHREAD_MUTEX_INITIALIZER;

// ------ Forward Declaration------ //
void usage();
void help();
void parseAddress(Server* Server, const char* arg);
int createSocket();
void getConnectionInfo(Server* Server);
int  connectTo(Server* server, int timeout);
void* receiveMessage(void* arg);
int sentFile();
int readFile();
int send_sticker();
int check_relation();
// -------------------------------- //

int main(int argc, char* argv[]){
    if(argc != 2) usage();
    char read_buf[MAX_BUF];
    char send_buf[MAX_BUF];
    line_cnt = 0;
    parseAddress(&server, argv[1]); // parse argument from "ip:port" -> server.ip, server.port
    if(connectTo(&server, TIMEOUT) < 0){
        printf("timeout when connect to %s\n", server.ip);
        exit(-1);
    }

    printf("connect to server at %s:%s, fd = %d\n", server.ip, server.port, server.connect_fd);
    // printf("login as ?\n");
    // scanf("%s", usr_name);
    // printf("logged in as %s\n", usr_name);
    while(1){
       // printf("------Welcome to CNLine-----\n");
        printf("Register or Login? ");
        scanf("%s", option);
        if(strncmp(option,"register", 1) == 0){
            printf("please enter username: ");
            scanf("%s", usr_name);
            printf("please enter password: ");
            scanf("%s", pwd);
            sprintf(send_buf, "register:name %s pwd %s", usr_name, pwd);
            send(server.connect_fd, send_buf, strlen(send_buf), 0);
            printf("Registered successfully, please login to start chatting.\n");
        }
        else if(strncmp(option,"login", 1) == 0){
            char rcv_buf[MAX_BUF];
            int success = 0;
            printf("please enter username: ");
            scanf("%s", usr_name);
            printf("please enter password: ");
            scanf("%s", pwd);
            sprintf(send_buf, "login:name %s pwd %s", usr_name, pwd);
            send(server.connect_fd, send_buf, strlen(send_buf), 0);
            while(1){
                // printf("Checking this account\n");
                int rcv = recv(server.connect_fd, rcv_buf, MAX_BUF, 0);
                if(rcv > 0){
                    char* check = strtok(rcv_buf,"\n");
                    // printf("%s\n",check);
                    if(strncmp(check,"0",1) == 0){
                        printf("Not existing this user\n");
                    }
                    else if(strncmp(check,"2",1) == 0){
                        printf("Password incorrect\n");
                    }
                    else if(strncmp(check,"1",1) == 0){
                        printf("Log in as %s\n",usr_name);
                        success = 1;
                    }
                    break;
                }
            }
            if(success) break;
        }
    }
    pthread_t receiveMessage_thread;
    Thread_data data;
    data.server = &server, data.usr_name = usr_name, data.chat_usr = chat_usr;
    pthread_create(&receiveMessage_thread, NULL, receiveMessage, (void*)&data);
    help();
    while(1){
        fgets(read_buf, MAX_BUF, stdin);          // get user input from console
        if(strcmp(read_buf, "\n") == 0) continue; // input of "\n" will be ignored
        if(read_buf[0] == ':'){
            if(strncmp(read_buf, ":chat", 5) == 0){
                printf("chat with ?\n");
                scanf("%s", chat_cand);
                sprintf(send_buf, "chat:name %s friend %s", usr_name, chat_cand);
                send(server.connect_fd, send_buf, strlen(send_buf), 0);
                wait_chat = 1;
                while(wait_chat);                
            }else if(strncmp(read_buf, ":logout", 7) == 0){
                close(server.connect_fd);
                printf("logged out\n");
                return 0;
            }else if(strncmp(read_buf, ":sendfile", 9) == 0){
                sentFile();
            }else if(strncmp(read_buf, ":readfile", 9) == 0){
                readFile();
            }else if(strncmp(read_buf, ":help", 5) == 0){
                help();
            }else if(strncmp(read_buf, ":sticker", 8) == 0){
                send_sticker();
            }else if(strncmp(read_buf, ":add", 4) == 0){
                char friend_name[MAX_STR];
                printf("friend's name ?\n");
                scanf("%s", friend_name);
                sprintf(send_buf, "add:name %s friend %s", usr_name, friend_name);
                send(server.connect_fd, send_buf, strlen(send_buf), 0);
            }
        }else{
            //printf("%s\n", read_buf);
            sprintf(send_buf, "send: from %s to %s msg %s", usr_name, chat_usr, read_buf);
            send(server.connect_fd, send_buf, strlen(send_buf), 0);
            line_cnt++;
            //sprintf(send_buf, "read: %s %s %d/", usr_name, chat_usr, line_cnt);
            //send(server.connect_fd, send_buf, strlen(send_buf), 0);
        }
    }
    pthread_join(receiveMessage_thread, NULL);
    close(server.connect_fd);
    return 0;
}

void usage(){
    printf("[usage]:./client <IP:port>\n");
    exit(-1);
}

void help(){
    printf("--------------Welcome to CNLine--------------\n");
    printf("Type \":chat\" to enter or change chat room.\n");
    printf("Type \":add\" to add friends.\n");
    printf("Type \":sticker\" to send stickers.\n");
    printf("Type \":sendfile\" to send file.\n");
    printf("Type \":readfile\" to download file to your local directory.\n");
    printf("Type \":logout\" to logout.\n");
    printf("Type \":help\" for help.\n");
    printf("---------------------------------------------\n");
}

void parseAddress(Server* Server, const char* arg){
    char str[MAX_STR];
    strcpy(str, arg);
    char* ptr = strtok(str, ":");
    strcpy(Server->ip, ptr);
    ptr += strlen(ptr)+1;
    strcpy(Server->port, ptr);
}

int createSocket(){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1){
        printf("Failed to create socket\n");
        exit(-1);   
    }
    return fd;
}

void getConnectionInfo(Server* Server){ 
    memset(&Server->connection_info, 0, sizeof(Server->connection_info));
    Server->connection_info.sin_family = AF_INET;
    if(strcmp(Server->ip, "NULL") != 0) Server->connection_info.sin_addr.s_addr = inet_addr(Server->ip);
    else Server->connection_info.sin_addr.s_addr = inet_addr("240.0.0.0");
    Server->connection_info.sin_port = htons(atoi(Server->port));
    Server->connect_fd = createSocket();
    fcntl(Server->connect_fd, F_SETFL, O_NONBLOCK);
}

int connectTo(Server* server, int timeout){
    getConnectionInfo(server);
    fd_set connectSet;
    FD_ZERO(&connectSet);
    FD_SET(server->connect_fd, &connectSet);
    struct timeval tv = {timeout/1000, (timeout%1000)*1000};
    //printf("tv:%ld sec %d usec\n", tv.tv_sec, tv.tv_usec);
    struct timeval start, end;
    connect(server->connect_fd,(const struct sockaddr*) &server->connection_info, sizeof(server->connection_info));
    gettimeofday(&start, NULL);
    if(select(server->connect_fd+1, NULL, &connectSet, NULL, &tv) == 1){
        gettimeofday(&end, NULL);
        int so_error;
        socklen_t len = sizeof so_error;
        getsockopt(server->connect_fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            return 1;
        }else{
            close(server->connect_fd);
            return -1;
        }
    }
    close(server->connect_fd);
    return -1;
}

int sentFile(){
    printf("send what file ?\n");
    char query[MAX_BUF];
    char file_buf[MAX_BUF], sendMsg[3*MAX_STR+MAX_BUF+64];
    char *file_name;
    //scanf("%s", file_name);
    fgets(query, MAX_BUF, stdin);
    file_name = strtok(query, " \n");
    while(file_name != NULL){
    if (strcmp(file_name, " ") == 0)continue;
    //printf("filename: %s\n", file_name);
    FILE* send_file = fopen(file_name, "rb");
    if(send_file == NULL){
        printf("%s file not exit.\n", file_name);
    }else{
        int read_len = 0, total_read_len = 0;
        struct timeval tv = {0, 8000};
        while((read_len = fread(file_buf, 1, MAX_BUF, send_file)) != 0){
            total_read_len += read_len;
            sprintf(sendMsg, "sendFile: from %s to %s filename %s size %d msg ", usr_name, chat_usr, file_name, read_len);
            //printf("sendMsg:%s\n", sendMsg);
            int msg_size = strlen(sendMsg);
            char* cptr = &sendMsg[msg_size];
            for(int i = 0; i < read_len; i++, cptr++) *cptr = file_buf[i];
            while(!server_ok);
            pthread_mutex_lock(&server_ok_lock);
            fd_set connectSet;
            FD_ZERO(&connectSet);
            FD_SET(server.connect_fd, &connectSet);
            while(select(server.connect_fd+1, NULL, &connectSet, NULL, &tv) == 0);
            send(server.connect_fd, sendMsg, msg_size + read_len, 0);
            server_ok = 0;
            pthread_mutex_unlock(&server_ok_lock);
        }
        while(!server_ok);
        pthread_mutex_lock(&server_ok_lock);
        fd_set connectSet;
        FD_ZERO(&connectSet);
        FD_SET(server.connect_fd, &connectSet);
        sprintf(sendMsg, "send: from %s to %s msg <FILE--%s>", usr_name, chat_usr, file_name);
        while(select(server.connect_fd+1, NULL, &connectSet, NULL, &tv) == 0);
        send(server.connect_fd, sendMsg, strlen(sendMsg), 0);
        pthread_mutex_unlock(&server_ok_lock);
        printf("%s sent. (%d bytes)\n", file_name, total_read_len);
        line_cnt++;
    }
    file_name = strtok(NULL, " \n");
    }
    return 0;
}

int readFile(){
    char sendMsg[MAX_BUF], *file_name, query[MAX_BUF];
    printf("read what file?\n");
    //scanf("%s", file_name);
    fgets(query, MAX_BUF, stdin);
    int offset = 0;
    file_name = strtok(query, " \n");
    while(file_name != NULL){
        if (strcmp(file_name, " ") == 0)continue;
        sprintf(sendMsg, "readFile: from %s to %s filename %s", usr_name, chat_usr, file_name);
        send(server.connect_fd, sendMsg, strlen(sendMsg), 0);
        read_req_ok = 0;
        while(!read_req_ok);
        offset += strlen(file_name)+1;
        file_name = strtok(query+offset, " \n");
    }
    return 0;
}

int send_sticker(){
    char stk[4][10] = {"(>_<)", "(-_-)", "(^_^)", "(#_#)"};
    char send_buf[MAX_BUF];
    int n;
    printf("which sticker?\n");
    for(int i = 0; i < 4; i++){
        printf("%d.: %s\n", i, stk[i]);
    }
    scanf("%d", &n);
    printf("%s\n", stk[n]);
    if (n > 4) return 0;
    sprintf(send_buf, "send: from %s to %s msg %s", usr_name, chat_usr, stk[n]);
    send(server.connect_fd, send_buf, strlen(send_buf), 0);
    line_cnt++;
    return 0;
}

int check_relation(){

    

    return 0;
}

void* receiveMessage(void* arg){
    Thread_data* data = (Thread_data*)arg;
    int rcv_size, connect_fd = data->server->connect_fd;
    char* usr_name = data->usr_name, *chat_usr = data->chat_usr;
    char rcv_buf[MAX_BUF], send_buf[2*MAX_STR + 64];
    memset(rcv_buf, 0, MAX_BUF);
    memset(send_buf, 0, 2*MAX_STR + 64);
    fd_set connectSet;
    while(1){
        FD_ZERO(&connectSet);
        FD_SET(connect_fd, &connectSet);
        struct timeval tv = {TIMEOUT/1000, (TIMEOUT%1000)*1000};
        if(select(connect_fd+1, &connectSet, NULL, NULL, &tv) == 1){
            rcv_size = recv(connect_fd, rcv_buf, MAX_BUF, 0);
            if(rcv_size == 0){
                // try reconnecting to server
                close(connect_fd);
                printf("[ERROR]: server disconnected.\n");
                printf("[STATUS]: try reconnecting...\n");
                while(connectTo(data->server, TIMEOUT) < 0)  close(connect_fd);
                printf("[STATUS]: reconnected.\n");
            }
            if(strncmp(rcv_buf, "ack", 3) == 0){
                pthread_mutex_lock(&server_ok_lock);
                server_ok = 1;
                pthread_mutex_unlock(&server_ok_lock);
            }else if(strncmp(rcv_buf, "sendFile", 8) == 0){
                //printf("msg: %s\n", rcv_buf);
                char* ptr = strtok(rcv_buf, " ");
                ptr = strtok(NULL, " ");
                char *filename = ptr;
                ptr = strtok(NULL, ":");
                char *size_s = ptr;
                char *msg = ptr+strlen(size_s)+1;
                int size = atoi(size_s);
                //printf("file_name: %s\n", filename);
                //printf("size: %d\n", size);
                if(size == -1){
                    printf("%s received (%d bytes)\n", filename, rcv_total_cnt);
                    rcv_total_cnt = 0;
                    read_req_ok = 1;
                    server_ok = 1;
                }else{
                    FILE* transfer_file = fopen(filename, "ab");
                    fwrite(msg, 1, size, transfer_file);
                    fclose(transfer_file);
                    rcv_total_cnt += size;
                    char ack[] = "ack";
                    send(connect_fd, ack, strlen(ack), 0);
                    //printf("msg: %s\n", msg);
                }  
            }else if(wait_chat){
            	if(strncmp(rcv_buf,"0",1) == 0){
            	    printf("You hasn't added %s as your friend\n",chat_cand);
            	    wait_chat = 0;
            	}
            	else if(strncmp(rcv_buf,"2",1) == 0){
            	    printf("%s hasn't added you as his friend\n",chat_cand);
            	    wait_chat = 0;
            	}
            	else if(strncmp(rcv_buf,"3",1) == 0){
            	    printf("%s hasn't registered\n",chat_cand);
            	    wait_chat = 0;
            	}
            	else if(strncmp(rcv_buf,"1",1) == 0){
            	    printf("You two are friend\n");
            	    strncpy(chat_usr,chat_cand, strlen(chat_cand));
            	    printf("start chat with %s\n", chat_usr);
            	    line_cnt = 0;
            	    wait_chat = 0;
            	}
            	
        	}else{
                printf("%s", rcv_buf);
                if(strncmp(rcv_buf, "file not exit!", 6) == 0) read_req_ok = 1;
                pthread_mutex_lock(&server_ok_lock);
                server_ok = 1;
                pthread_mutex_unlock(&server_ok_lock);
            }
            char* ptr = strchr(rcv_buf, ':');
            while(ptr != NULL){
                line_cnt++;
                ptr = strchr(ptr+1, ':');
            }
            memset(rcv_buf, 0, MAX_BUF);
        }else if(server_ok == 1){ // nothing to receive from server, check if there is any new message.
            FD_ZERO(&connectSet);
            FD_SET(connect_fd, &connectSet);
            struct timeval tv = {TIMEOUT/1000, (TIMEOUT%1000)*1000};
            if(select(connect_fd+1, NULL, &connectSet, NULL, &tv) == 1){
                sprintf(send_buf, "read: %s %s %d", usr_name, chat_usr, line_cnt);
                send(connect_fd, send_buf, strlen(send_buf), 0);
                memset(send_buf, 0, 2*MAX_STR + 64);
                pthread_mutex_lock(&server_ok_lock);
                server_ok = 0;
                pthread_mutex_unlock(&server_ok_lock);
            }
        }
        memset(rcv_buf, 0, MAX_BUF);
    }
}