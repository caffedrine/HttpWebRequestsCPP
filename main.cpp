#include "HttpWebRequests.hpp"
#include <iostream>
#include <cstdio>

using namespace std;

int main()
{
    HttpWebRequest req;
    req.setUrl("checkip.dyndns.com");

    req.proxy.enable = true;
    req.proxy.proxy_type = PROXY_SOCKS5;
    req.proxy.ipOrHostname = "176.31.96.198";
    req.proxy.port = 3128;

    req.headers.httpMethod =  GET;
    req.headers.keepCookies = true;
    req.headers.cookieContainer = "";
    req.headers.userAgent = "Easy HttpWebRequests 0.1/ www.howtofix.pro";
    req.headers.connection = "close";
    req.headers.postContent = "login=1&type=submit";
    //req.headers.custom = "If-Modified-Since: *\r\n"; //Don't forget about \r\n.

    std::string document, header;

    if( req.downloadDocument(header, document) )
    {
        cout << "HEADER: " << endl << header << endl << endl;
        cout << "DOCUMENT: " << endl << document  << endl;
    }
    else
    {
        cout << "Failed to download document!" << endl;
        cout << "Error: " << req.getLastError() << endl;
    }
    return 0;
}

