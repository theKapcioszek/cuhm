#pragma once

#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ssl.h>

#define RESPONSE_NOT_OK 2
#define VERBAL 300

#define BUF_LEN 1048577 //1MB + 1B buffer
#define RESP_HEAD_LEN 1024

typedef struct {
    char *data;
    size_t count;
} StringView;

typedef struct {

  SSL *ssl;
  SSL_CTX* ctx;
  int sockfd;

} SslCtxSock;

void sv_chop_left(StringView *sv, size_t n);
void sv_chop_right(StringView *sv, size_t n);
StringView sv_chop_by_delim(StringView *sv, char delim);
char *sv_to_cstring(char *cstring,StringView *sv);

SslCtxSock CUHM_ConnectToServiceSSL(char* hostname, char* port);
int CUHM_RetrieveFileSSL(char* hostname, char* path, SSL* ssl, FILE* fp, int verbal_flag);
void CUHM_Cleanup(SSL *ssl, SSL_CTX *ctx,int sockfd);

#if defined(CUHM_IMPLEMENTATION)

void sv_chop_left(StringView *sv, size_t n){
  
  if(n > sv->count) n = sv->count;
  sv->count -= n;
  sv->data += n;

  return;
}

void sv_chop_right(StringView *sv, size_t n){
  
  if(n > sv->count) n = sv->count;
  sv->count -= n;

  return;
}


StringView sv_chop_by_delim(StringView *sv, char delim){

  if(strchr(sv->data,delim) == NULL) return *sv;
  size_t i = 0;
  while (i < sv->count && sv->data[i] != delim){
    i += 1;
  }
  if(i < sv->count){
    StringView result = {0};
    result.data = sv->data;
    result.count = i;
    
    sv_chop_left(sv, i+1);
    return result;
  }
}

char *sv_to_cstring(char *cstring,StringView *sv){
  char *result = cstring;
  for(int i = 0; i < sv->count; i++){
    cstring[i] = sv->data[i];
  }
  return result;
}

SslCtxSock CUHM_ConnectToServiceSSL(char* hostname, char* port){

  SSL_library_init();
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

  struct addrinfo hints, *result;
  int le_socket = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  getaddrinfo(hostname,port,&hints,&result);

  le_socket = socket(result->ai_family,result->ai_socktype,result->ai_protocol);
  connect(le_socket,result->ai_addr,result->ai_addrlen);

  freeaddrinfo(result);

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl,le_socket);
  SSL_set_tlsext_host_name(ssl, hostname);
  SSL_connect(ssl);

  SslCtxSock struct_to_return = {0};

  struct_to_return.ssl = ssl;
  struct_to_return.ctx = ctx;
  struct_to_return.sockfd = le_socket;

  return struct_to_return;

}

int CUHM_RetrieveFileSSL(char* hostname, char* path, SSL* ssl, FILE* fp, int verbal_flag){

  char buffer[BUF_LEN]; memset(&buffer, 0, sizeof(buffer));
  char message[1024]; memset(&message, 0 ,sizeof(message));
  char header[RESP_HEAD_LEN]; memset(&header, 0, sizeof(header));
  strcpy(message,"GET /");strcat(message,path);strcat(message," HTTP/1.1\r\nHost: ");strcat(message,hostname);strcat(message,"\r\nConnection: close\r\n\r\n");
  SSL_write(ssl,message,strlen(message));
  while(SSL_read(ssl,buffer,1) != 0){
    strcat(header,buffer);
    if (strstr(header,"\r\n\r\n") != NULL) break;
  }
 
  if (strstr(header,"200 OK") == NULL){
    int i = -1;
    if(verbal_flag == VERBAL) while(header[i] != '\n') printf("%c",header[++i]); //i++ didnt work (on my machine at least)

    return RESPONSE_NOT_OK;
  }

  if(verbal_flag == VERBAL)printf("%s",header);
  char *chopped_header = strstr(header,"Content-Length: ");

  StringView sv_chopped_header = {0};
  sv_chopped_header.data = chopped_header;
  sv_chopped_header.count = strlen(chopped_header);

  sv_chop_by_delim(&sv_chopped_header,' ');
  StringView sv_cs_content_length = sv_chop_by_delim(&sv_chopped_header, '\n');
  char cs_content_length[100];
  sv_to_cstring(cs_content_length,&sv_cs_content_length);

  size_t read_bytes = 0;
  size_t bytes_recieved = 0;
  size_t bytes_to_recieve = atoi(cs_content_length);

  while(1){
    if(verbal_flag == VERBAL){ printf("\e[2k\r%.2lf%c",((double)bytes_recieved/bytes_to_recieve)*100,'%'); fflush(stdout); }
    read_bytes = SSL_read(ssl,buffer,BUF_LEN-1);
    bytes_recieved += read_bytes;
    fwrite(buffer,1,read_bytes,fp);
    if(bytes_recieved >= bytes_to_recieve) break;
  }

  return 0;

}


void CUHM_Cleanup(SSL *ssl, SSL_CTX *ctx,int sockfd){

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  shutdown(sockfd,1);

  return;
}

#endif //CUHM_IMPLEMENTATION
