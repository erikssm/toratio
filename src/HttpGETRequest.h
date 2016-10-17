/*
 * HttpGETRequest.h
 *
 *  Created on: Oct 12, 2016
 *      Author: aa
 */

#ifndef HTTPGETREQUEST_H_
#define HTTPGETREQUEST_H_
#include <string>

using namespace std;

namespace toratio
{
class HttpGETRequest
{
private:
	string m_getString;
public:

	HttpGETRequest(const string& src)
	{
		m_getString = src;
	}

	string& getString()
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
	string getParameterValue(const string& name)
	{
		string ret;

		size_t pos1 = m_getString.find(name + "=");
		if (pos1 != std::string::npos)
		{
			pos1 += name.length() + 1;
			size_t pos2 = m_getString.find("&", pos1);
			if (pos2 == std::string::npos)
				pos2 = m_getString.find(" ", pos1);
			if (pos2 != std::string::npos)
				ret = m_getString.substr(pos1, (pos2 - pos1));
		}
		return ret;
	}

	/**
	 * Get port from GET request
	 */
	string getPort()
	{
		string hp = getHostAndPort();
		size_t pos = hp.find(":");
		if (pos != std::string::npos)
		{
			return hp.substr(pos + 1, hp.length() - pos - 1);
		}

		return {};
	}

	/**
	 * Get host from GET request
	 */
	string getHost()
	{
		string hp = getHostAndPort();
		string port = hp;
		size_t pos = hp.find(":");
		if (pos != std::string::npos)
		{
			port = hp.substr(0, pos);
		}

		return port;
	}

	/**
	 * Return value of GET string
	 */
	long long getParameterValueLLong(const string& name, bool& error)
	{
		error = false;
		char *pError = nullptr;
		long nBytes = strtol(getParameterValue(name).c_str(), &pError, 10);
		if (pError != nullptr && *pError != 0)
			error = true;

		return nBytes;
	}

	/**
	 * Set value of GET string
	 */
	bool setParameterValue(const string& param, const string& value)
	{
		string ret;

		size_t pos = m_getString.find(param + "=");
		if (pos != std::string::npos)
		{
			size_t pos2 = m_getString.find("&", pos);
			string bytes = m_getString.substr(pos + param.length() + 1, (pos2 - pos - 1));
			m_getString = m_getString.substr(0, pos + param.length()) + "=" + value + m_getString.substr(pos2);

			return true;
		}

		return false;
	}

private:
	/**
	 * Get host:port from GET request
	 */
	string getHostAndPort()
	{
		string firstLine = m_getString;
		size_t n = m_getString.find("\n\r");
		if (n != std::string::npos)
			firstLine = m_getString.substr(0, n + 1);

		string search1 = "GET http";

		size_t end = -1;
		size_t start = firstLine.find(search1, 0);

		if (start != std::string::npos)
			start = firstLine.find("://", start + search1.length());

		if (start == std::string::npos)
		{
			return {};
		}

		end = firstLine.find("/", start + 3);
		if (end == std::string::npos)
		{
			cout << "end not found" << endl;
			return {};
		}

		string host = firstLine.substr(start + 3, end - (start + 3));

		return host;
	}
};
} // namespace toratio

#endif /* HTTPGETREQUEST_H_ */
