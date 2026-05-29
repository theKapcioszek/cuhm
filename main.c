#define CUHM_IMPLEMENTATION
#include "cuhm.h"

#define MAX_PATH_LEN 100
#define MAX_HOST_LEN 100

int main(int argc, char **argv)
{

  if(argc < 3){
    printf("\n\nUsage: %s <URL> <output file path>\n\n",argv[0]);
    return 1;
  }
  
  char hostname[MAX_HOST_LEN]; memset(&hostname, 0, sizeof(hostname));
  char path[MAX_PATH_LEN]; memset(&path, 0, sizeof(path));

  StringView le_URL = {0};
  le_URL.data = argv[1];
  le_URL.count = strlen(argv[1]);

  StringView sv_hostname = sv_chop_by_delim(&le_URL, '/');
  sv_to_cstring(hostname,&sv_hostname);
  sv_to_cstring(path,&le_URL);

  SslCtxSock le_sockets = CUHM_ConnectToServiceSSL(hostname,"443");

  FILE* fp = fopen(argv[2],"wb");
  float progress = 0;
  if(CUHM_RetrieveFile(hostname,path,&le_sockets,fp,&progress) != 0) {
    CUHM_Cleanup(le_sockets.ssl,le_sockets.ctx,le_sockets.sockfd); return RESPONSE_NOT_OK;
  };
  fclose(fp);

  CUHM_Cleanup(le_sockets.ssl,le_sockets.ctx,le_sockets.sockfd);

  return 0;
}
