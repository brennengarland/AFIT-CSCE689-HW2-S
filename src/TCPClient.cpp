#include "TCPClient.h"
#include "exceptions.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <netdb.h> 
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

/*
Author: Brennen Garland
Reference: https://beej.us/guide/bgnet/html, https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
*/



/**********************************************************************************************
 * TCPClient (constructor) - Creates a Stdin file descriptor to simplify handling of user input. 
 *
 **********************************************************************************************/

TCPClient::TCPClient() {
    std::cout << "Making Client\n";
    if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){throw socket_error("Failed to get socket");}
}

/**********************************************************************************************
 * TCPClient (destructor) - No cleanup right now
 *
 **********************************************************************************************/

TCPClient::~TCPClient() {

}

/**********************************************************************************************
 * connectTo - Opens a File Descriptor socket to the IP address and port given in the
 *             parameters using a TCP connection.
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPClient::connectTo(const char *ip_addr, unsigned short port) 
{
    std::cout << "Preparing Connection\n";
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip_addr);
    address.sin_port = htons( port );
    std::cout << "Client: Connecting to server...\n";
    if(connect(sock_fd, (struct  sockaddr *)&address, sizeof(address)) < 0)
    {
        shutdown(sock_fd, 2); 
        throw socket_error("Connection error");
    }
}

/**********************************************************************************************
 * handleConnection - Performs a loop that checks if the connection is still open, then 
 *                    looks for user input and sends it if available. Finally, looks for data
 *                    on the socket and sends it.
 * 
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPClient::handleConnection() {
    // std::cout << "Handling connection\n";
    char msg[1000];
    int rec_len;
    bool conn = true;
    while(conn)
    {
        if((rec_len = recv(sock_fd, msg, 1000, 0)) < 0) { 
            throw socket_error("Could not receive");
        } else if(rec_len == 0) {
            std::cout << "\nServer Disconnected\n";
            closeConn();
            return;
        }
        // Add null character to string for security
        msg[rec_len] = '\0';
        // std::cout << "Received: " << rec_len << " bytes\n";
        // std::cout << "Message:\n";
        std::cout << msg;
        bool cmd_valid = false;
        while(!cmd_valid)
        {
            // std::cout << "Send Command: " << std::endl;

            std::string cmd;
            std::getline(std::cin, cmd);
            // std::cout <<  "Input: " << cmd << "\n";
            // std::cout << "Size of Input: " << cmd.length() << std::endl;
            

             if(cmd.length() >= 20)
            {
                // Server inputs are very small and so anything to larger can be rejected by the client
                std::cout << "Please enter a valid command. That was for too large!\n";
            }
            else
            {   
                int bytes_sent;

                bytes_sent = send(sock_fd, cmd.c_str(), strlen(cmd.c_str()), 0);
                // std::cout << "Sent: " << bytes_sent << " bytes\n";
                cmd_valid = true;

            }
            
        }

    }

}

/**********************************************************************************************
 * closeConnection - Your comments here
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPClient::closeConn() {
    close(sock_fd);
}


