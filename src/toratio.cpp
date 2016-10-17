#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <iosfwd>
#include <string>
#ifndef _WIN32
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#else
#include <winsock2.h>
#endif
#include "HttpGETRequest.h"
#include "network.h"
#include "toratio.h"

using namespace std;

#define DEBUG					1
#define USE_CLIENT_THREADS 		0 // linux only

int 		g_daemon {}; // daemon mode
string 		g_listenPort {};

namespace
{
enum class EXIT_CODES
{
	FAIL_OPEN_LISTEN_SOCK = 1,
	FAIL_TO_BIND,
	FAIL_PARSING_PORT,
	INVALID_ARGUMENTS
};

constexpr int 		socketQueueSize {20};
constexpr double 	uploadMultiplier {1.1};
constexpr char 		logFile[] = "/tmp/toratio.log";

bool stop = false;
} // namespace

void DebugPrint(const char *format, ...); // forward function declaration

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
    char buff[1024];
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
    string out{buff};
	replace_if(out.begin(), out.end(), IsNotAlphaNumChar, '.');

    if( !g_daemon )
    {
    	printf("%s", out.c_str());
    }
    else
    {
    	// print to file
    	static std::ofstream log;
    	if( !log.is_open() )
    	{
			log.open(logFile, ofstream::out | ofstream::app);
			log << std::endl << "-------------toratio log------------" << std::endl;
    	}
    	log << out;
    }
}

#ifndef _WIN32
/**
 * ctrl+c signal handler
 */
void SignalHandler(int s)
{
	if( SIGINT == s )
	{
		printf("Received signal SIGINT\n");
	}
	else if( SIGTERM == s )
	{
		printf("Received signal SIGTERM \n");
	}
	else
	{
		printf("Received signal 0x%x \n",s);
	}
	stop = true;
}

#else
/**
* ctrl+c signal handler
*/
BOOL WINAPI SignalHandler(DWORD s) {

	if (s == CTRL_C_EVENT)
	{
		printf("Received signal 0x%x \n", s);
		stop = true;
	}

	return TRUE;
}
#endif

/**
 * Prints memory in hex format
 * buff must be 3x mem ( i.e. each byte = 2 chars )
 */
void MemToString(const unsigned char *mem, const int nMem, char * buff, const int nBuff)
{
	int n = 0;
	for (int i = 0; (i < nMem) && (n < nBuff - 2); i++)
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
int QueryDestinationServer(HSOCKET servSockfd, const string& message, std::vector< char >& recvBuff, int & bytesRead)
{
	if (servSockfd < 1)
	{
		DebugPrint("ERROR cannot process request: invalid socket");
		return -1;
	}

	if( message.empty() )
	{
		DebugPrint("ERROR cannot process request: message is empty");
		return -1;
	}

	// send request
//	DebugPrint("ProcessDestServer: sending message to server (%d bytes).. \n%s", nMessage, message);
	DataVector data;
	std::copy(message.begin(), message.end(), std::back_inserter(data));
	if ( WriteSocket(servSockfd, data, data.size()) != 0 )
	{
		DebugPrint("ERROR writing to destination server socket");
		return -3;
	}

	// read response
	if (ReadFromSocket(servSockfd, recvBuff, bytesRead) != 0)
	{
		DebugPrint("ERROR reading from destination server socket");
		return -4;
	}

	DebugPrint("Server response (%d bytes): \n%s", bytesRead, recvBuff);

	return 0;
}


/**
 * Resolve host name and return IP
 */
const string ResolveServerHostName(const string& host)
{
	static map<string, string> s_ipCache;
	string ip;

	// try to find ip in resolve cache
	if (s_ipCache.find(host) != s_ipCache.end() )
	{
		ip = s_ipCache[host];
		DebugPrint("Found host name \"%s\" (%s) in cache", host.c_str(), ip.c_str());
		return ip;
	}

	ip = ResolveHostName(host);
	if (  ip.empty() )
	{
		DebugPrint("Unable to resolve hostname (%s)", host.c_str());
		return ip;
	}

	s_ipCache[host] = ip;
	DebugPrint("Resolved server ip: %s", ip.c_str());

	return ip;
}

/**
 *	Process GET request from client
 */
void * ProcessClientRequest(void *arg)
{
	int n;
	DataVector msg403;
	{
		const string str403 { "HTTP/1.0 403 Forbidden\r\nStatus Code: 403"
				"\r\nContent-Length: 0"
				"\r\nConnection: close\r\n\r\n"
		};
		std::copy(str403.begin(), str403.end(), std::back_inserter(msg403));
	}

	DebugPrint("New client connection");

	toratio::SocketPtr clientSocket;
	try
	{
		clientSocket.reset( new toratio::Socket{ *(HSOCKET *)arg });
	} catch( std::exception& ex )
	{
		DebugPrint("ERROR could not create socket: %s", ex.what());
		return nullptr;
	} catch( ... )
	{
		DebugPrint("ERROR could not create socket (unknown error)");
		return nullptr;
	}

	// read command from client
	DebugPrint("Waiting for request from client..");

	DataVector requestMsg(1024 * 2, 0);
	if (ReadFromSocket(*clientSocket, requestMsg, n) != 0)
	{
		DebugPrint("ERROR reading from client socket");
		return nullptr;
	}

	if (strncmp(requestMsg.data(), "\r\n\r\n", 4) == 0 )
	{
		DebugPrint("Close msg received from client");
		return nullptr;
	}

	bool GETrequest = strncmp(requestMsg.data(), "GET", 3) == 0;
	bool CONNECTrequest = strncmp(requestMsg.data(), "CONNECT", 7) == 0;
	if ( !GETrequest )
	{
		static int nErrors {};
		constexpr int maxWarings { 20 };

		if (nErrors < maxWarings)
		{
			string req {requestMsg.begin(), requestMsg.end()};
			replace(req.begin(), req.end(), '\r', '\0');
			replace(req.begin(), req.end(), '\n', '\0');

			DebugPrint("%s", req.c_str());
			DebugPrint("This is not GET request, closing..");

			if (maxWarings == ++nErrors)
				DebugPrint("Further similar messages will be suppressed");
		}

		// send 403 message to client
		WriteSocket(*clientSocket, msg403, msg403.size());

		return nullptr;
	}

	// extract host from header
	/**
	 * GET http://testing.com/ann?uk=lsdfjlsdf&info_hash=%06%ceE%f8ac%e9%ff%aa%cd%83%f4p%dc%111%ac~%5c%27&peer_id=-BE9223-1Bh.R0uW.xeO&port=58000&uploaded=0&downloaded=0&left=12080071962&corrupt=0&redundant=0&compact=1&numwant=200&key=3434349c&no_peer_id=1&supportcrypto=1&event=started&ipv4=11.111.11.111 HTTP/1.1
		Host: localhost:1234
		User-Agent: Deluge 1.3.6
		Accept-Encoding: gzip
		Connection: close
	 *
	 */
//	int serverPort = 80;
//	char host[1024];
//	bool hasPort = false;
//	memset(host, 0, 1024);
//	char *pHost = strchr(requestMsg, ' ');
//	if ( pHost != nullptr)
//	{
//		pHost++; // skip blank
//		char *pStart;
//		if (getRequest)
//			pStart = strchr(pHost, '/');
//		else
//			pStart = pHost;
//		char *pEnd = nullptr;
//		if ( pStart != nullptr )
//		{
//			if (getRequest)
//			{
//				pStart += 2; // skip '//'
//				pEnd = strchr(pStart, '/');
//			}
//			else if (connectRequest)
//			{
//				pEnd = strchr(pStart, ' ');
//			}
//		}
//		if (pStart != nullptr && pEnd != nullptr )
//		{
//			strncpy(host, pStart, pEnd - pStart);
//		}
//
//		// check if port is present
//		char *pColon = strchr(host, ':');
//		if (pColon != nullptr)
//		{
//			*pColon = 0;
//			serverPort = strtol(++pColon, nullptr, 10);
//			hasPort = true;
//			DebugPrint("Setting destination server port to %d", serverPort);
//		}
//	}
//	if ( host[0] == 0 )
//	{
//		DebugPrint("Host string not found, closing..");
//		WriteSocket(clientSockfd, msg403, strlen(msg403));
//		if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
//		return nullptr;
//	}

	if (GETrequest)
	{
		DebugPrint("New GET request from client: %s", requestMsg.data());

		toratio::HttpGETRequest request{ {requestMsg.begin(), requestMsg.end()} };

		// extract PORT
		int serverPort {80};
		bool customPort {false};
		string port = request.getPort();
		if (!port.empty())
		{
			try
			{
				serverPort = stoi(port);
				customPort = true;
			} catch (...)
			{
				DebugPrint("Invalid port was specified: %s", port.c_str());
				return nullptr;
			}
		}

		// resolve server ip
		string host {request.getHost()};
		DebugPrint("Request host: \"%s\", port: %d", host.c_str(), serverPort);

		string serverIp { ResolveServerHostName(host) };
		if (serverIp.empty())
		{
			WriteSocket(*clientSocket, msg403, msg403.size());
			return nullptr;
		}

		// replace host name
		size_t nHost = request.getString().find("Host: ");
		if (nHost != string::npos)
		{
			size_t nNewline = request.getString().find("\r\n", nHost);
			if (nNewline != string::npos)
			{
				string newHostStr{"Host: "};
				newHostStr += string(host);
				if (customPort)
					newHostStr += string{":"} + std::to_string(serverPort);

				request.getString() = request.getString().replace(nHost, (nNewline - nHost), newHostStr);

				// replace GET string
				size_t nHttp = request.getString().find("GET http");
				if (nHttp != string::npos)
				{
					nHttp += 4;
					string tmp = "http://" + string{host};
					if (customPort)
						tmp += string(":") + std::to_string(serverPort);
					request.getString() = request.getString().replace(nHttp, tmp.length(), string{""});
				}
			}
		}

		// modify uploaded parameter
		bool error {};
		long long nUpBytes = request.getParameterValueLLong("uploaded", error);
		if (error)
		{
			DebugPrint("Error retrieving 'uploaded' param from GET string ('%s') ", requestMsg);
		}
		else
		{
			long long nDownBytes = request.getParameterValueLLong("downloaded", error);
			long long newUploadedBytes { 0 };
			if (!error)
			{
				if (nUpBytes < nDownBytes)
					newUploadedBytes = (long long)(nDownBytes * uploadMultiplier);
				else
					newUploadedBytes = (long long)(nUpBytes * uploadMultiplier);
			}
			else
			{
				DebugPrint("Warn: failed to retrieve 'downloaded' param from GET string ('%s') ", requestMsg);
				newUploadedBytes = (long long)(nUpBytes * uploadMultiplier);
			}

			if ( newUploadedBytes >= 0 )
			{
				string byteStr { std::to_string( newUploadedBytes ) };
				DebugPrint("Setting 'uploaded' to '%s'", byteStr.c_str());
				request.setParameterValue("uploaded", byteStr );
			}
			else
			{
				DebugPrint("Error: uploaded bytes < 0 (original request: '%s')", requestMsg);
			}
		}

		// query dest server
		toratio::SocketPtr serverSocket;
		try
		{
			serverSocket.reset( new toratio::Socket{serverIp, serverPort});
		} catch( std::exception& ex )
		{
			DebugPrint("ERROR could not create socket: %s", ex.what());
			return nullptr;
		} catch( ... )
		{
			DebugPrint("ERROR could not create socket (unknown error)");
			return nullptr;
		}

		DebugPrint("Processing request: %s", request.c_str());

		DataVector serverResponse;
		try
		{
			serverResponse.resize(1024 * 1024 * 5);
		} catch (...)
		{
			DebugPrint("Not enough free memory, cant send request to destination server..");
			return nullptr;
		}
		int bytesRead = 0;
		int result = QueryDestinationServer(*serverSocket, request.getString(), serverResponse, bytesRead);
		if (result != 0)
		{
			DebugPrint("ERROR in ProcessDestServer (%d)", result);
			return nullptr;
		}

		DebugPrint("Sending server response to client (%d bytes)", bytesRead);
		if (WriteSocket(*clientSocket, serverResponse, bytesRead) != 0)
		{
			DebugPrint("ERROR writing to client socket");
			return nullptr;
		}
	}
	else if (CONNECTrequest)
	{
		DebugPrint("HTTP CONNECT is not supported yet");

//		char buff[2048];
//
//		DebugPrint("Processing CONNECT request..");
//
//		// query dest server
//		HSOCKET servSock = ConnectSocket(serverIp, serverPort);
//		if (servSock < 0)
//		{
//			DebugPrint("ERROR invalid server socket descriptor (CONNECT failed, code: %d)", servSock);
//			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
//			return nullptr;
//		}
//		DebugPrint("Connected to destination server (CONNECT)");
//
//		static const char * http200 = "HTTP/1.0 200 Connection established\r\n\r\n";
//		if ( WriteSocket(clientSockfd, http200, strlen(http200)) != 0 )
//		{
//			DebugPrint("ERROR writing to client socket");
//			if ( clientSockfd > 0 ) { CloseSocket(clientSockfd); }
//			if ( servSock > 0 ) { CloseSocket(servSock); }
//			return nullptr;
//		}
//		DebugPrint("Connected to destination server (CONNECT)");
//
//		// read from client
//		while ( ReadFromSocket(clientSockfd, buff, sizeof(buff), n) == 0 && n > 0)
//		{
//			DebugPrint("(CONNECT) read from client %d bytes: %s", n, buff);
//			// send to server
//			if ( WriteSocket(servSock, buff, n) != 0 )
//			{
//				DebugPrint("ERROR writing to server socket (CONNECT, msg:\"%s\")", buff);
//				break;
//			}
//			DebugPrint("(CONNECT) sent to server %d bytes: %s", n, buff);
//
//			// read server response
//			if ( ReadFromSocket(servSock, buff, sizeof(buff), n) != 0 && n > 0)
//			{
//				DebugPrint("ERROR reading server response (CONNECT)");
//				break;
//			}
//			DebugPrint("(CONNECT) read from server %d bytes: %s", n, buff);
//
//			// send back to client
//			if ( WriteSocket(clientSockfd, buff, n) != 0 )
//			{
//				DebugPrint("ERROR writing to client socket (CONNECT, msg:\"%s\")", buff);
//				break;
//			}
//			DebugPrint("(CONNECT) sent back to client %d bytes: %s", n, buff);
//		}
//
//		if ( servSock > 0 ) { CloseSocket(servSock); }
	}

	DebugPrint("Client request process finished succesfully, closing socket");

	return nullptr;
}

#ifdef _WIN32
struct WinSockInitializer
{
	WinSockInitializer()
	{

		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != NO_ERROR) {
			throw runtime_error{"WSAStartup() failed with error: " + std::to_string(iResult)};
		}
	}

	~WinSockInitializer()
	{
		WSACleanup();
	}
};
#endif

bool ParseOptions( int argc, char *argv[] )
{
	int opt;

	while ((opt = getopt(argc, argv, "d")) != -1)
	{
		switch (opt)
		{
		case 'd':
			g_daemon = 1;
			break;
		default: // invalid argument
			return false;
		}
	}

	if (optind >= argc)
	{
		// no argument supplied, used default port
		g_listenPort = {	"8080"};
	}
	else
	{
		g_listenPort = {	argv[optind]};
	}

	return true;
}

int main(int argc, char *argv[])
{
	if( !ParseOptions(argc, argv) )
	{
		printf( "Usage: %s [d] <LISTEN_PORT>\r\n", argc ? argv[0] : "toratio" );
		printf( "Options: \r\n" );
		printf( "\t -d \t daemon mode \r\n" );

		return static_cast<int>(EXIT_CODES::INVALID_ARGUMENTS);
	}

#ifndef _WIN32
	// set up signal hadler for ctrl+c
	struct sigaction sigIntHandler;
	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, nullptr);
	sigaction(SIGTERM, &sigIntHandler, nullptr);
#else
	if (!SetConsoleCtrlHandler(SignalHandler, TRUE)) {
		DebugPrint("ERROR: Could not set control handler");
		return 4;
	}

	unique_ptr<WinSockInitalizer> initalizerPtr;
	try
	{
		initalizerPtr.reset(new WinSockInitalizer);
	} catch (...)
	{
		DebugPrint("ERROR: unknown WinSockInitalizer error");
	}
#endif

	if( g_daemon )
	{
		daemon( 0, 0 );
	}

	HSOCKET listenSockFd,clientSockFd;
	socklen_t clilen;
	int listenPort {8080};
	struct sockaddr_in serv_addr = {}, cli_addr;

	listenSockFd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSockFd < 0)
	{
		DebugPrint("ERROR opening listen socket");
		return static_cast<int>(EXIT_CODES::FAIL_OPEN_LISTEN_SOCK);
	}

	try
	{
		listenPort = stoi( g_listenPort );
	} catch( ... )
	{
		DebugPrint("ERROR invalid listening port was specified: '%s'", g_listenPort);
		return static_cast<int>(EXIT_CODES::FAIL_PARSING_PORT);
	}

	if (listenPort < 1 || listenPort > 65535)
	{
		DebugPrint("Invalid port number was specified: %s", g_listenPort);
		return static_cast<int>(EXIT_CODES::FAIL_PARSING_PORT);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(listenPort);
	if (bind(listenSockFd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		DebugPrint("ERROR on binding listening socket, quitting..");
		return static_cast<int>(EXIT_CODES::FAIL_TO_BIND);
	}
	listen(listenSockFd, socketQueueSize);
	clilen = sizeof(cli_addr);

	DebugPrint("%s running on port %d..", argv[0], listenPort);

	while (stop != true)
	{
		clientSockFd = accept(listenSockFd, (struct sockaddr *) &cli_addr, &clilen);
		if (stop)
			break;

		if ( USE_CLIENT_THREADS )
		{
#ifndef _WIN32
			pthread_t t;
			pthread_create(&t, nullptr, &ProcessClientRequest, &clientSockFd);
			pthread_detach( t );
#else
			ProcessClientRequest(&clientSockFd);
#endif
		}
		else
		{
			ProcessClientRequest(&clientSockFd);
		}
	}

	DebugPrint("Closing listening socket..");
#ifdef _WIN32
	closesocket(listenSockFd);
#else
	close(listenSockFd);
#endif

	DebugPrint("%s has shut down", argv[0]);
	return 0;
}

// todo rewrite code to c++ 11
