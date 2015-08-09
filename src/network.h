/*
 * network.h
 *
 *  Created on: Aug 8, 2015
 *      Author: aa
 */

#ifndef NETWORK_H_
#define NETWORK_H_


int ReadFromSocket(int sock, char *buffer, int nData, int &nRead);
int WriteSocket(int sock, const char *buffer, int nData);
int ResolveHostname(const char * hostname , char* ip, int size);
int ConnectSocket(const char *destIP, int port);

#endif /* NETWORK_H_ */
