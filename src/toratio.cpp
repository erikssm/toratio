#include "toratio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <string>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <map>
#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#else
#include <winsock2.h>
#endif

#include "network.h"

using namespace std;

#define DEBUG					1
#define USE_CLIENT_THREADS 		0 // linux only

static const double s_uploadMultiplier = 1.1;
static map<string, string> s_ipCache;
static bool stop = false;

void DebugPrint(const char *format, ...); // forward function declaration

class GetRequest
{
private:
	string m_getString;
public:

	GetRequest(const string& src)
	{
		m_getString = src;
	}

	string& GetString()
	{
		return m_getString;
	}

	const char * c_str()
	{
		return m_getString.c_str();
	}

	/**
	 * Return value of GET string
	 */
	string GetParameterValue(const string& name)
	{
		string ret;

		size_t pos1 = m_getString.find(name + "=");
		if (pos1 != std::string::npos)
		{
			pos1 += name.length() + 1;
			size_t pos2 = m_getString.find("&", pos1);
			if (pos2 != std::string::npos)
				ret = m_getString.substr(pos1, (pos2 - pos1));
		}
		return ret;
	}

	/**
	 * Return value of GET string
	 */
	long long GetParameterValueLLong(const string& name, bool& error)
	{
		error = false;
		char *pError = NULL;
		long nBytes = strtol(GetParameterValue(name).c_str(), &pError, 10);
		if (pError != NULL && *pError != 0)
			error = true;

		return nBytes;
	}

	/**
	 * Set value of GET string
	 */
	void SetParameterValue(const string& param, const string& value)
	{
		string ret;

		size_t pos = m_getString.find(param + "=");
		if (pos != std::string::npos)
		{
			size_t pos2 = m_getString.find("&", pos);
			string bytes = m_getString.substr(pos + param.length() + 1, (pos2 - pos - 1));
			m_getString = m_getString.substr(0, pos + param.length()) + "=" + value + m_getString.substr(pos2);
		}
	}
};

/**
 *	Closes socket
 */
void CloseSocket(HSOCKET s)
{
#ifdef _WIN32
	closesocket(s);
#else
	close(s);
#endif
}
/**
 * Returns true if char is not alphanumeric
 */
inline bool IsNotAlphaNumChar(const char c)
{
	if (c != '\r' && c != '\n' && (c < 32 || c > 125) )
		return true;
	return false;
}
/**
 * Print debug message
 */
void DebugPrint(const char *format, ...)
{
	if ( DEBUG == 0 )
		return;

    va_list args;
    va_start(args, format);
    char buff[1024]; // get rid of this hard-coded buffer
    char tmp[1024];
#ifndef _WIN32
    pthread_t id = pthread_self();
#else
	ULONG id = 0;
#endif
    snprintf(tmp, 1023, "[%lu] %s\n", id, format);
    vsnprintf(buff, 1023, tmp, args);
    va_end(args);

    // replace non alpha characters
    string out(buff);
    replace_if(out.begin(), out.end(), IsNotAlphaNumChar, '.');

    printf("%s", out.c_str());
}

#ifndef _WIN32
/**
 * ctrl+c signal handler
 */
void SignalHandler(int s)
{
	printf("\nReceived signal 0x%x \n",s);
	stop = true;
}

#else
/**
* ctrl+c signal handler
*/
BOOL WINAPI SignalHandler(DWORD s) {

	if (s == CTRL_C_EVENT)
	{
		printf("\nReceived signal 0x%x \n", s);
		stop = true;		
		WSACleanup();
	}

	return TRUE;
}
#endif

/**
 * Prints memory in hex format
 * buff must be 3x mem ( i.e. each byte = 2 chars )
 */
void MemToString(const unsigned char *mem, const int memSize, char * buff, const int buffSize)
{
	int n = 0;
	for ( int i = 0; (i < memSize) && (n < buffSize - 2); i++)
	{
		if ( mem[i] == 10 )
			snprintf(&buff[n], 4, "\\n ");
		else if ( mem[i] == 13 )
			snprintf(&buff[n], 4, "\\r ");
		else
			snprintf(&buff[n], 4, "%02x ", mem[i]);
		n += 3;
	}
}

/**
 * Send request to dest server and read response
 */
int ProcessDestServer(int servSockfd, const char *message, char *recvBuff, int buffSize, int & bytesRead)
{
	if ( servSockfd < 1)
	{
		DebugPrint("ERROR cannot process request: invalid socket");
		return -1;
	}

	if ( recvBuff == NULL )
		return -2;

	memset(recvBuff, 0, buffSize * sizeof(char));

	// send request
	int nMessage = strlen(message);
//	DebugPrint("ProcessDestServer: sending message to server (%d bytes).. \n%s", nMessage, message);
	if ( WriteSocket(servSockfd, message, nMessage) != 0 )
	{
		DebugPrint("ERROR writing to socket");
		return -3;
	}

	// read response
	if ( ReadFromSocket(servSockfd, recvBuff, buffSize - 1, bytesRead) != 0)
	{
		DebugPrint("ERROR reading from dest server socket");
		return -4;
	}

	DebugPrint("Server response (%d bytes): \n%s", bytesRead, recvBuff);

	return 0;
}

/**
 *	Process GET request from client
 */
void * ProcessClientConn(void *arg)
{
	int n;
	static const char * msg403 = "HTTP/1.0 403 Forbidden\r\nStatus Code: 403"
			"\r\nContent-Length: 0"
			"\r\nConnection: close\r\n\r\n";

	DebugPrint("New client connection");

	char requestMsg[1024 * 2];
	HSOCKET clientSockfd = *((int *)arg);

	if (clientSockfd < 0)
	{
		DebugPrint("ERROR invalid socket descriptor");
		return NULL;
	}

	// read command from client
	memset(requestMsg, 0, sizeof(requestMsg));
	DebugPrint("Waiting for request from client..");

	if ( ReadFromSocket(clientSockfd, requestMsg, sizeof(requestMsg) - 1, n) != 0)
	{
		DebugPrint("ERROR reading from client socket");
		CloseSocket(clientSockfd);
		return NULL;
	}

	if (strncmp(requestMsg, "\r\n\r\n", 4) == 0 )
	{
		DebugPrint("Close msg received from client");
		CloseSocket(clientSockfd);
		return NULL;
	}

	bool getRequest = strncmp(requestMsg, "GET", 3) == 0;
	bool connectRequest = strncmp(requestMsg, "CONNECT", 7) == 0;
	if ( !getRequest )
	{
		string req(requestMsg);
		replace(req.begin(), req.end(), '\r', '\0');
		replace(req.begin(), req.end(), '\n', '\0');

		DebugPrint("%s", req.c_str());
		DebugPrint("This is not GET request, closing..");

		WriteSocket(clientSockfd, msg403, strlen(msg403));

		CloseSocket(clientSockfd);
		return NULL;
	}

	DebugPrint("New request from client: %s", requestMsg);

	// extract host from header
	bool hasPort = false;
	int serverPort = 80;
	char host[1024];
	memset(host, 0, 1024);
	char *pHost = strchr(requestMsg, ' ');
	if ( pHost != NULL)
	{
		pHost++; // skip blank
		char *pStart;
		if (getRequest)
			pStart = strchr(pHost, '/');
		else
			pStart = pHost;
		char *pEnd = NULL;
		if ( pStart != NULL )
		{
			if (getRequest)
			{
				pStart += 2; // skip '//'
				pEnd = strchr(pStart, '/');
			}
			else if (connectRequest)
			{
				pEnd = strchr(pStart, ' ');
			}
		}
		if (pStart != NULL && pEnd != NULL )
		{
			strncpy(host, pStart, pEnd - pStart);
		}

		// check if port is present
		char *pColon = strchr(host, ':');
		if (pColon != NULL)
		{
			*pColon = 0;
			serverPort = strtol(++pColon, NULL, 10);
			hasPort = true;
			DebugPrint("Setting destination server port to %d", serverPort);
		}
	}
	if ( host[0] == 0 )
	{
		DebugPrint("Host string not found, closing..");
		WriteSocket(clientSockfd, msg403, strlen(msg403));
		if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
		return NULL;
	}
	DebugPrint("Request host: (%s)", host);

	// resolve server ip
	char serverIp[1024];
	memset(serverIp, 0, 1024);

	// tro to find ip in resolve cache
	if (s_ipCache.find(host) != s_ipCache.end() )
	{
		strcpy(serverIp, s_ipCache[host].c_str());
		DebugPrint("Found host name \"%s\" (%s) in cache", host, serverIp);
	}
	else if ( ResolveHostname(host, serverIp, 1024) != 0 )
	{
		DebugPrint("Unable to resolve hostname (%s)", host);

		WriteSocket(clientSockfd, msg403, strlen(msg403));

		if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
		return NULL;
	}
	else
	{
		s_ipCache[host] = serverIp;
		DebugPrint("Resolved server ip: %s", serverIp);
	}

	if (getRequest)
	{
		GetRequest newRequest(requestMsg);

		// replace host name
		size_t nHost = newRequest.GetString().find("Host: ");
		if (nHost != string::npos)
		{
			size_t nNewline = newRequest.GetString().find("\r\n", nHost);
			if (nNewline != string::npos)
			{
				stringstream convert;
				convert << serverPort;

				string newHostStr("Host: ");
				newHostStr += string(host);
				if (hasPort)
					newHostStr += string(":") + convert.str();

				newRequest.GetString() = newRequest.GetString().replace(nHost, (nNewline - nHost), newHostStr);

				// replace GET string
				size_t nHttp = newRequest.GetString().find("GET http");
				if (nHttp != string::npos)
				{
					nHttp += 4;
					string tmp = "http://" + string(host);
					if (hasPort)
						tmp += string(":") + convert.str();
					newRequest.GetString() = newRequest.GetString().replace(nHttp, tmp.length(), string(""));
				}
			}
		}

		// modify uploaded parameter
		bool error;
		long long nUpBytes = newRequest.GetParameterValueLLong("uploaded", error);
		if (!error)
		{
			long long nDownBytes = newRequest.GetParameterValueLLong("downloaded", error);
			long long newBytes = 0;
			if (!error)
			{
				if (nUpBytes < nDownBytes)
					newBytes = (long long)(nDownBytes * s_uploadMultiplier);
				else
					newBytes = (long long)(nUpBytes * s_uploadMultiplier);
			}
			else
			{
				DebugPrint("Error retrieving \"downloaded\" param from GET string (\"%s\") ", requestMsg);
				newBytes = (long long)(nUpBytes * s_uploadMultiplier);
			}

			if ( newBytes >= 0 )
			{
				stringstream convert;
				convert << newBytes;
				DebugPrint("Setting \"uploaded\" to \"%s\"", convert.str().c_str());
				newRequest.SetParameterValue("uploaded", convert.str());
			}
			else
				DebugPrint("Error: uploaded bytes < 0 (original request: \"%s\")", requestMsg);
		}
		else
		{
			DebugPrint("Error retrieving \"uploaded\" param from GET string (\"%s\") ", requestMsg);
		}

		// query dest server
		HSOCKET servSock = ConnectSocket(serverIp, serverPort);
		if (servSock < 0)
		{
			DebugPrint("ERROR invalid server socket descriptor");
			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
			return NULL;
		}

		int bytesRead = 0;
		int buffSize = 1024 * 1024 * 5;
		char *buffResp = (char *)malloc(buffSize * sizeof(char));
		DebugPrint("Processing request: %s", newRequest.c_str());
		int proc = ProcessDestServer(servSock, newRequest.c_str(), buffResp, buffSize, bytesRead);
		if ( proc != 0 )
		{
			DebugPrint("ERROR in ProcessDestServer (%d)", proc);
			free(buffResp);
			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
			return NULL;
		}

		DebugPrint("Sending response to client (%d bytes)", bytesRead);
		if ( WriteSocket(clientSockfd, buffResp, bytesRead) != 0)
			DebugPrint("ERROR writing to client socket");

		// cleanup
		if ( servSock > 0 ) { CloseSocket(servSock); }
		free(buffResp);
	}
	else if (connectRequest)
	{
		char buff[2048];

		DebugPrint("Processing CONNECT request..");

		// query dest server
		HSOCKET servSock = ConnectSocket(serverIp, serverPort);
		if (servSock < 0)
		{
			DebugPrint("ERROR invalid server socket descriptor (CONNECT)");
			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
			return NULL;
		}
		DebugPrint("Connected to destination server (CONNECT)");

		static const char * http200 = "HTTP/1.0 200 Connection established\r\n\r\n";
		if ( WriteSocket(clientSockfd, http200, strlen(http200)) != 0 )
		{
			DebugPrint("ERROR writing to client socket (CONNECT)");
			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
			if ( servSock > 0 ) { CloseSocket(servSock); }
			return NULL;
		}
		DebugPrint("Connected to destination server (CONNECT)");

		// read from client
		while ( ReadFromSocket(clientSockfd, buff, sizeof(buff), n) == 0 && n > 0)
		{
			DebugPrint("(CONNECT) read from client %d bytes: %s", n, buff);
			// send to server
			if ( WriteSocket(servSock, buff, n) != 0 )
			{
				DebugPrint("ERROR writing to server socket (CONNECT, msg:\"%s\")", buff);
				break;
			}
			DebugPrint("(CONNECT) sent to server %d bytes: %s", n, buff);

			// read server response
			if ( ReadFromSocket(servSock, buff, sizeof(buff), n) != 0 && n > 0)
			{
				DebugPrint("ERROR reading server response (CONNECT)");
				break;
			}
			DebugPrint("(CONNECT) read from server %d bytes: %s", n, buff);

			// send back to client
			if ( WriteSocket(clientSockfd, buff, n) != 0 )
			{
				DebugPrint("ERROR writing to client socket (CONNECT, msg:\"%s\")", buff);
				break;
			}
			DebugPrint("(CONNECT) sent back to client %d bytes: %s", n, buff);
		}

		if ( servSock > 0 ) { CloseSocket(servSock); }
	}

	DebugPrint("Client request process finished succesfully, closing socket");
	if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }

	return NULL;
}

int main(int argc, char *argv[])
{
#ifndef _WIN32
	// set up signal hadler for ctrl+c
	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
#else
	if (!SetConsoleCtrlHandler(SignalHandler, TRUE)) {
		DebugPrint("ERROR: Could not set control handler");
		return 4;
	}

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		DebugPrint("WSAStartup() failed with error: %d\n", iResult);
		return 3;
	}
#endif

	HSOCKET listenSockFd,clientSockFd;
	socklen_t clilen;
	int portno;
	struct sockaddr_in serv_addr, cli_addr;
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s PORT\n", argv[0]);
		return 1;
	}
	fprintf(stdout, "%s running on port %s..\n", argv[0], argv[1]);

	listenSockFd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSockFd < 0)
	{
		DebugPrint("ERROR opening listen socket");
#ifdef _WIN32
		WSACleanup();
#endif
		return 1;
	}
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	portno = atoi(argv[1]);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(portno);
	if (bind(listenSockFd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		DebugPrint("ERROR on binding");
#ifdef _WIN32
		WSACleanup();
#endif
		return 2;
	}
	listen(listenSockFd, 5);
	clilen = sizeof(cli_addr);

	while (stop != true)
	{
		clientSockFd = accept(listenSockFd, (struct sockaddr *) &cli_addr, &clilen);
		if (stop)
			break;

		if ( USE_CLIENT_THREADS )
		{
#ifndef _WIN32
			pthread_t t;
			pthread_create(&t, NULL, &ProcessClientConn, &clientSockFd);
#else
			ProcessClientConn(&clientSockFd);
#endif
		}
		else
		{
			ProcessClientConn(&clientSockFd);
		}
	}

	DebugPrint("Closing listening socket..");
	CloseSocket(listenSockFd);
#ifdef _WIN32
	WSACleanup();
#endif
	DebugPrint("%s has shut down", argv[0]);
	return 0;
}

// todo rewrite code to c++ 11
