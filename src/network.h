#ifndef NETWORK_H_
#define NETWORK_H_
#include "toratio.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#ifndef _WIN32
#define HSOCKET int
#else
#define HSOCKET SOCKET
#define socklen_t int
#endif

int ReadFromSocket(HSOCKET sock, char *buffer, int nData, int &nRead);
int WriteSocket(HSOCKET sock, const char *buffer, int nData);
int ResolveHostName(const char * hostname , char* ip, int size);
HSOCKET ConnectSocket(const char *destIP, int port);

#endif /* NETWORK_H_ */
