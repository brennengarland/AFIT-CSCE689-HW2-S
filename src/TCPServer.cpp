#include "TCPServer.h"
#include <stdexcept>
#include <netinet/in.h> 
#include "exceptions.h"
#include <fcntl.h>
#include <sys/time.h>
#include "TCPConn.h"
#include <map>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>

/*
Author: Brennen Garland
Reference: https://beej.us/guide/bgnet/html, https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
*/


TCPServer::TCPServer() {
    
}


TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) 
{
    
    struct sockaddr_in address;
    // Create socket to listen for incoming connections
    if((listener_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        // Unrecoverable: if we cannot obtain a socket, we cannot
        // have a server.
        throw std::runtime_error("Failed to create socket");
    }

    // Set listener to Non-Blocking
    fcntl(listener_sock, F_SETFL, O_NONBLOCK);

    int opt = 1;
    if(setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        throw std::runtime_error("Failed to set socket options");
    }
    // Fill in address details such as port and IP for binding
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip_addr);
    address.sin_port = htons( port );
    // Bind listener to port
    if(bind(listener_sock, (struct  sockaddr *)&address, sizeof(address)) < 0)
    {
        // Unrecoverable: if our listener socket does not bind, we do not have
        // a server.
        throw std::runtime_error("Binding error");
    }

    std::fstream log_file("server.log", std::ios_base::app);
    time_t now = time(0);
    tm *ltime = localtime(&now);
    log_file << "--------------------------------------" << "\n";
    log_file << "Time: " << ltime->tm_hour << ":";
    log_file << ltime->tm_min << ":" << ltime->tm_sec << "\n";
    log_file << "Date: " << 1900 + ltime->tm_year << " ";
    log_file << 1 + ltime->tm_mon << " " << ltime->tm_mday << "\n";
    log_file << "Server Starting\n";
    log_file << "IP Address: " << ip_addr << " Port: " << port << "\n";
    log_file.close();
    
   
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() 
{
    // Two sets are needed, one for all sockets and another that will be modified by the read each time
    fd_set all_sock, read_sock;
    // Max sock will keep track of the socket range we need to be checking
    int max_sock, new_sock;
    // This keep tracks of the sockets and their TCPConn objects
    std::map<int, TCPConn*> connections;

    // Start listening on one socket
    if(listen(listener_sock, 2) < 0)
    {
        // Unrecoverable: a server must be able to listen
        throw std::runtime_error("Hung Up on Listening");
    }

    // std::cout << "Started Listening..\n";

    // Add this listener socket to our master list
    FD_SET(listener_sock, &all_sock);
    // Set as max socket until we find another
    max_sock = listener_sock;

    while(true)
    {
        // Read sock is modified by select so we must reset it each time
        read_sock = all_sock;
        // std::cout << "\nServer: Looping\n";

        if(select(max_sock+1, &read_sock, NULL, NULL, NULL) < 0)
        {
            // Unrecoverable: if we cannot find the socket, we wont be able
            // to process any data
            throw socket_error("Select error");
        }
        std::cout << "New Data!\n";
        // Loop through all of our sockets and check which ones have data
        for(int i=0; i <= max_sock; i++)
        {
            // If this socket is in the set of sockets that has data
            if(FD_ISSET(i, &read_sock))
            {
                // New connection because the listener socket has data
                if(i == listener_sock)
                {
                    std::cout << "New Connection!\n";
                    TCPConn* new_conn = new TCPConn();
                    if(new_conn->accept_conn(listener_sock) == false)
                    {
                        // Recoverable: Sometimes it may not accept a connection
                        throw socket_error("Error: Accepting new Connection");
                    }

                    if(new_conn->isConnected()){
                        new_sock = new_conn->getSocket();

                        if(new_sock > max_sock) {max_sock = new_sock;}
                        // Add the new socket to our master list
                        FD_SET(new_sock, &all_sock);
                        connections.insert({new_sock, new_conn});

                    }
                }
                // Data from an existing connection
                else
                {
                    std::cout << "Existing Connection\n";
                    // Loop through our map of sockets and tcpconn objects
                    for(auto const& [key, val] : connections)
                    {
                        if(key == i)
                        {
                            // If the connection is closed, clear it from our list
                            val->handleConnection();
                            std::cout << "Connection: " << val->isConnected() << "\n";
                            if(!val->isConnected())
                            {
                                FD_CLR(key, &all_sock);
                                connections.erase(key);
                            }
                        }
                    }
                }
            }
        }

    }

}

/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {
    
    close(listener_sock);
}