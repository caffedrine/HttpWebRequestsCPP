#include <winsock2.h>
#include <string>
#include <algorithm>
#include <vector>

typedef enum
{
    PROXY_HTTP,
    PROXY_SOCKS4 = 4,
    PROXY_SOCKS5 = 5
} ProxyType;

typedef enum
{
    GET,
    POST,
    HEAD
} HttpMethod;

typedef struct
{
    std::string fullUrl  = "";
    std::string protocol = "";
    std::string hostname = "";
    std::string path     = "";
} UrlDetails;

typedef struct
{
    bool enable              = false;
    std::string ipOrHostname = "127.0.0.1";
    u_short port             = 8080;
    ProxyType proxy_type     = PROXY_HTTP;
}ProxyInfo;

typedef struct
{
    HttpMethod httpMethod       = GET;
    bool keepCookies            = false;
    std::string cookieContainer = "";
    std::string userAgent       = "Easy HttpWebRequests 0.1/ www.howtofix.pro";
    std::string connection      = "close";
    std::string custom          = "";
    std::string postContent     = "";

}HeadersInfo;

class HttpWebRequest
{
public:
    HttpWebRequest();
    ~HttpWebRequest();

    //Variables
    ProxyInfo proxy;
    HeadersInfo headers;

    u_short httpPort = 80;
    int timeOut      = 10000; // Not implemented, yet!

    //Methods
    bool downloadDocument(std::string &header, std::string &content);

    //Sets
    void setUrl(std::string url);

    //Gets
    std::string getLastError();

private:
    //Variables
    UrlDetails urlInfo;
    std::string lastError = "";

    //Methods
    bool downloadDocumentNoProxy(std::string &respHeader, std::string &respContent);
    bool downloadDocumentUseSocksProxy(std::string &respHeader, std::string &respContent);
    bool downloadDocumentUseHttpProxy(std::string &respHeader, std::string &respContent);

    bool buildHeaders(std::string &header1, std::string &header2);
};

class CSocks
{
    typedef enum
    {
        SOCKS4 = 4,
        SOCKS5 = 5,
    }SockVersion;

    typedef struct
    {
        SockVersion version  = SOCKS4;
        std::string IPAddr   = "";
        std::string hostname = "";
        u_short port         = 1080;
    }SocksInfo;

    typedef struct
    {
        std::string IPAddr   = "";
        std::string hostname = "";
        u_short port         = 80;
    }DestInfo;

public:
    //Constructors/Destructors
    CSocks(std::string socketIPorHost, u_short socketPort, int version);
    ~CSocks();

    //Our methods
    SOCKET Connect();
    int sendData(SOCKET s, const void *buffer, int buflen);
    int recvData(SOCKET s, void *buffer, int buflen);

    //Sets
    void setDestination(std::string destIPorHostname, u_short destPort);

    //Gets
    std::string getLastError();

private:
    //Variables
    SocksInfo socksInfo;
    DestInfo destInfo;
    std::string lastError = "";

    //Main methods
    SOCKET connectSOCKS4(SOCKET hSocksSocket);
    SOCKET connectSOCKS5(SOCKET hSocksSocket);

    //Gets, sets and all the stuff
    void setLastError(std::string err);

    //Util functions
    std::string resolveHostname(std::string hostname);
    bool isValidIPv4(std::string ip);
    bool isValidHostname(std::string hostname);
};

namespace utils
{
    std::string getHostFromUrl(std::string &url);
    bool getHostIP(unsigned long &ipAddr, std::string urlOrHostnameOrIp);

    namespace IPAddr
    {
        bool isValidIPv4(std::string &ip);
        std::string reverseIpAddress(std::string ip);
        std::string decimalToDottedIp(unsigned long ip);
        unsigned long stripToDecimal(std::string &ip);
    }

    namespace strings
    {
        std::vector<std::string> split(std::string &s, char delim);
        std::string removeSubstrs(std::string &source, std::string pattern);
    }
};
