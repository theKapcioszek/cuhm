#define CUHM_IMPLEMENTATION
#include "cuhm.h"

#define MAX_PATH_LEN 100
#define MAX_HOST_LEN 100

enum protocol {
  HTTP,
  HTTPS
};

int main(int argc, char **argv)
{

  if(argc < 3){
    printf("\n\nUsage: %s <URL> <output file path>\n\n",argv[0]);
    return 1;
  }
 
  int le_protocol = -1;
  if (strstr(argv[1],"https://") != NULL) {argv[1] += strlen("https://"); le_protocol = HTTPS;}
  if (strstr(argv[1],"http://") != NULL) {argv[1] += strlen("http://"); le_protocol = HTTP;}
  if (le_protocol == -1 ) {printf("\nPrepending 'https://' at the start of %s\n",argv[1]);}

  char hostname[MAX_HOST_LEN]; memset(&hostname, 0, sizeof(hostname));
  char path[MAX_PATH_LEN]; memset(&path, 0, sizeof(path));

  StringView le_URL = {0};
  le_URL.data = argv[1];
  le_URL.count = strlen(argv[1]);

  StringView sv_hostname = sv_chop_by_delim(&le_URL, '/');
  sv_to_cstring(hostname,&sv_hostname);
  sv_to_cstring(path,&le_URL);

  SslCtxSock le_sockets = le_protocol == HTTPS ? CUHM_ConnectToServiceSSL(hostname,"443") : CUHM_ConnectToService(hostname,"80");
  if (le_sockets.sockfd == 0) {printf("\nHostname %s does not exist\n",hostname); return -2;}
  printf("\nConnected to %s\n",hostname);
  HeaderData le_header_data = CUHM_RetrieveHeaderHTTP(hostname,path,&le_sockets);
  printf("Sent a HTTP request... Response: %d\n",le_header_data.code);

  if (le_header_data.code != 200) return -3;

  FILE* fp = fopen(argv[2],"wb");
  float progress = 0;
  if(CUHM_RetrieveFile(hostname,path,&le_sockets,&le_header_data,fp,&progress) != 0) {
    CUHM_Cleanup(le_sockets.ssl,le_sockets.ctx,le_sockets.sockfd); 
    printf("\nFailed to retrieve the file\n");
    return -1;
  };
  fclose(fp);

  CUHM_Cleanup(le_sockets.ssl,le_sockets.ctx,le_sockets.sockfd);

  return 0;
}
