#include "toratio.h"
#include "network.h"

/**
 * Remove chunk size information from chunked HTTP response
 */
void ParseChunkedMessage(char *msg)
{
	char *p, *pRN;
	int nChunk, iter = 0;

	if (msg == NULL || strstr(msg, "Transfer-Encoding: chunked") == NULL)
		return;

	p = strstr(msg, "\r\n\r\n"); // fine eof header
	p += 4;

	do
	{
		pRN = NULL;
		nChunk = strtol(p, &pRN, 16);
		if (pRN != NULL && *pRN != '\r')
		{
//			printf("Error parsing chunked encoding msg (src: \"%s\" pRN:\"%s\")\n", p, pRN);
			return;
		}
//		printf("next chunk size is %d (0x%x) \n", nChunk, nChunk);

		if (nChunk != 0)
		{
			memmove(p, pRN, nChunk);

			// move to next chunk
			p = pRN + 2 + nChunk;
		}
		else
		{
			memmove(p, pRN, 5); // final \r\n\r\n + string terminating \0
		}

		iter++;
	} while (nChunk != 0 && iter < 1000);
}

/**
 * Read from socket
 * returns 0 on success
 */
int ReadFromSocket(HSOCKET sock, char *buffer, int nBuffer, int &nRead)
{
	int tmp;
	nRead = 0;
	bool chunked = false;

	if (buffer == NULL)
		return 1;

	memset(buffer, 0, nBuffer);
	do
	{
#ifndef _WIN32
		tmp = read(sock, &buffer[nRead], nBuffer - nRead);
#else
		tmp = recv(sock, &buffer[nRead], nBuffer - nRead, 0);
#endif
		if (tmp > 0)
			nRead += tmp;

		if (!chunked)
			chunked = strstr(buffer, "Transfer-Encoding: chunked") != NULL;

		if ( chunked && strstr(buffer, "0\r\n\r\n") != NULL )
			break;
		else if ( strstr(buffer, "\r\n\r\n") != NULL ||  strstr(buffer, "\n\n") != NULL ) // eof msg received
			break;
	} while(tmp > 0);

	if (tmp < 0)
		return tmp;

//	if (chunked)
//		ParseChunkedMessage(buffer);

	return 0;
}

/**
 * Write to socket
 * returns 0 on success
 */
int WriteSocket(HSOCKET sock, const char *buffer, int nData)
{
	int tmp, n = 0;
	do
	{
#ifndef _WIN32
		tmp = write(sock, &buffer[n], nData - n);
#else
		tmp = send(sock, &buffer[n], nData - n, 0);
#endif
		if (tmp > 0)
			n += tmp;
	} while(tmp > 0 && n < nData);

	if (tmp < 0)
		return tmp;

	return 0;
}

/**
 * Resolve host name to ip
 */
int ResolveHostname(const char * hostname , char* ip, int nIp)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if (hostname == NULL || ip == NULL)
    	return 2;

    if (strcmp(hostname, "retracker.local") == 0)
    	return 3;

    if ( (he = gethostbyname( hostname ) ) == NULL)
        return 1;

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strncpy(ip , inet_ntoa(*addr_list[i]), nIp );
        return 0;
    }

    return 1;
}

/**
 * Connect socket
 */
HSOCKET ConnectSocket(const char *destIP, int port)
{
	HSOCKET sockfd = 0;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n ERROR : Could not create socket \n");
		return sockfd;
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, destIP, &serv_addr.sin_addr) <= 0)
	{
		printf("\n inet_pton error occured\n");
		return 1;
	}

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nERROR : Connect Failed \n");
		return -10;
	}

	return sockfd;
}
