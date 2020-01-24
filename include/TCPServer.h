#ifndef TCPSERVER_H
#define TCPSERVER_H

#pragma once

#include "Server.h"
#include <sys/socket.h>
#include <fstream>

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();

private:
   int listener_sock;
   // struct sockaddr_in address;


};


#endif
