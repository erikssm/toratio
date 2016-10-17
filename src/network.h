#ifndef NETWORK_H_
#define NETWORK_H_
#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <string>
#include <vector>

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

#define ERR_CONNECT_FAILED    -5
#define ERR_PTON_ERROR        -6

using DataVector = std::vector<char>;

namespace toratio
{
class Socket
{
public:
	Socket(const std::string& destIP, int port);
	Socket(HSOCKET socket);
	~Socket();
	operator HSOCKET() const;

private:
	Socket() = delete;
	HSOCKET m_socket;
};
using SocketPtr = std::unique_ptr<Socket>;
}

int ReadFromSocket(HSOCKET sock, DataVector& buffer, int &nRead);
int WriteSocket(HSOCKET sock, const DataVector& buffer, size_t bytes);
std::string ResolveHostName(const std::string& hostname);
HSOCKET ConnectSocket(const std::string& destIP, int port);

#endif /* NETWORK_H_ */
