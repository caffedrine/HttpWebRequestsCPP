# HttpWebRequestsCPP

A very simple and easy to use C++ Wrapper based on Winsock2.

Usefull when interacting with web pages.

Easily to integrate as it does not require external dependencies!

# Example:

main.cpp or the following sample:

```cpp
#include "HttpWebRequests.hpp"
#include <iostream>
#include <cstdio>

using namespace std;

int main()
{
    HttpWebRequest req;
    req.setUrl("checkip.dyndns.com");

    req.headers.httpMethod =  GET;
    req.headers.keepCookies = true;
    req.headers.cookieContainer = "";
    req.headers.userAgent = "Easy HttpWebRequests 0.1/ www.howtofix.pro";
    req.headers.connection = "close";

    // Store response here
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

```

# What it can do?

  * SOCKS5, SOCKS5 and HTTP proxy support implemented;
  * Implemented Cookie container like the one from .NET
  * Easy to use
  * Not implemented follow redirects and other advanced options. 
  * SSL not implemented, yet...
  
# To make your life easier:
Don't forget to add the following flags to your compiler: **-std=c++11 -static-libgcc -static-libstdc++**
And link the following libs: **gdi32.lib ws2_32.lib**
 
# Usefull 

Based on Winsock2. Obviously, it works under Windows, only!
