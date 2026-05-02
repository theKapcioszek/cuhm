#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ssl.h>

#define BUF_LEN 2
#define RESP_LEN 4096

typedef struct {
    char *data;
    size_t count;
}StringView;

int main(int argc, char **argv)
{

  if(argc < 2){
    printf("\n\nUsage: %s <domain name>\n\n",argv[0]);
    return 1;
  }
  
  char hostname[100]; memset(&hostname, 0, sizeof(hostname));
  strcpy(hostname,argv[1]);

  SSL_library_init();
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  
  struct addrinfo hints, *result;
  int le_socket = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  getaddrinfo(hostname,"443",&hints,&result);

  le_socket = socket(result->ai_family,result->ai_socktype,result->ai_protocol);
  connect(le_socket,result->ai_addr,result->ai_addrlen);

  freeaddrinfo(result);

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl,le_socket);
  SSL_set_tlsext_host_name(ssl, hostname);
  SSL_connect(ssl);

  char buffer[BUF_LEN]; memset(&buffer, 0, sizeof(buffer));
  char message[1024]; memset(&message, 0 ,sizeof(message)); 
  char response[RESP_LEN]; memset(&response, 0, sizeof(response));
  strcpy(message,"GET / HTTP/1.1\r\nHost: ");strcat(message,hostname);strcat(message,"\r\nConnection: close\r\n\r\n");
  SSL_write(ssl,message,strlen(message));
  while(SSL_read(ssl,buffer,BUF_LEN-1) != 0){
    strcat(response,buffer);
  }
  StringView response_sv = {0};
  response_sv.data = response;
  response_sv.count = strlen(response);

  printf("%s",response_sv.data);
  
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  shutdown(le_socket,1);

  return 0;
}
