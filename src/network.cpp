#include <cstring>
#include <stdexcept>
#include "network.h"

namespace toratio
{
Socket::Socket( const std::string& destIP, int port )
{
	HSOCKET sockfd = 0;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "\n ERROR : Could not create socket \n");
		m_socket =  sockfd;
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, destIP.c_str(), &serv_addr.sin_addr) <= 0)
	{
		throw std::runtime_error { "inet_pton error occured" };
	}

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		fprintf(stderr, "ERROR : Connect Failed (ip: %s, port: %d) \n", destIP.c_str(), port);
		std::string msg {
			"connect Failed (ip: " + destIP + ", port: " + std::to_string(port) + ")"
		};
		throw std::runtime_error { msg };
	}

	m_socket =  sockfd;
}

Socket::Socket(HSOCKET socket)
{
	if( socket < 0 )
	{
		throw std::invalid_argument { "Invalid socket" };
	}
	m_socket = socket;
}

Socket::~Socket()
{
	if ( m_socket > 0 )
	{
#ifdef _WIN32
		closesocket(m_socket);
#else
		close(m_socket);
#endif
	}
}

Socket::operator HSOCKET() const
{
	return m_socket;
}
}

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
int ReadFromSocket(HSOCKET sock, DataVector& buffer, int &nRead)
{
	int tmp;
	nRead = 0;
	bool chunked = false;

	if (!buffer.size())
		return 1;

	memset(buffer.data(), 0, buffer.size());
	do
	{
#ifndef _WIN32
		tmp = read(sock, &buffer.data()[nRead], buffer.size() - nRead);
#else
		tmp = recv(sock, &buffer[nRead], nBuffer - nRead, 0);
#endif
		if (tmp > 0)
			nRead += tmp;

		if (!chunked)
			chunked = strstr(buffer.data(), "Transfer-Encoding: chunked\r\n") != NULL;

		if ( chunked && strstr(buffer.data(), "0\r\n\r\n") != NULL )
			break;
		else if ( strstr(buffer.data(), "\r\n\r\n") != NULL ||  strstr(buffer.data(), "\n\n") != NULL ) // eof msg received
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
int WriteSocket(HSOCKET sock, const DataVector& buffer, size_t bytes)
{
	int tmp;
	size_t n {};

	do
	{
#ifndef _WIN32
		tmp = write(sock, &buffer[n], buffer.size() - n);
#else
		tmp = send(sock, &buffer[n], nData - n, 0);
#endif
		if (tmp > 0)
			n += tmp;
	} while(tmp > 0 && n < bytes && n < buffer.size());

	if (tmp < 0)
	{
		fprintf(stderr, "socket error: %s, bytes written: %lu\n", strerror(errno), n);
		return tmp;
	}

	return 0;
}

/**
 * Resolve host name to ip
 */
std::string ResolveHostName(const std::string& hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	if (hostname.empty())
	{
		return {};
	}

	if ("retracker.local" == hostname)
	{
		return {};
	}

	if ((he = gethostbyname(hostname.c_str())) == NULL)
	{
		return {};
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	for (int i {}; addr_list[i] != NULL; i++)
	{
		//Return the first one;
		return inet_ntoa(*addr_list[i]);
	}

	return {};
}

/**
 * Connect socket
 */
HSOCKET ConnectSocket(const std::string& destIP, int port)
{
	HSOCKET sockfd = 0;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "\n ERROR : Could not create socket \n");
		return sockfd;
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, destIP.c_str(), &serv_addr.sin_addr) <= 0)
	{
		fprintf(stderr, "\n inet_pton error occured\n");
		return ERR_PTON_ERROR;
	}

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		fprintf(stderr, "ERROR : Connect Failed (ip: %s, port: %d) \n", destIP.c_str(), port);
		return ERR_CONNECT_FAILED;
	}

	return sockfd;
}
