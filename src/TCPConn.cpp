#include "TCPConn.h"
#include <sys/types.h>
#include <netinet/in.h> 
#include <sys/socket.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include "exceptions.h"
#include <cstdlib>
#include <fstream>
#include <istream>
#include <string>
#include <arpa/inet.h>
#include <argon2.h>
#include <time.h>
#include <ctime>


/*
Author: Brennen Garland
Reference: https://beej.us/guide/bgnet/html, https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
*/

TCPConn::TCPConn() {
    
    // Random seed for our options
    srand(time(0));

    pwdMgr = new PasswdMgr("passwd");
}


/*******************************************************************************************
 *  accept_conn - Accepts a connection, checks if it's a whitelisted IP, then prompts client
 *                  for a username.
 *
 *    Params:  server - socket to accept
 *
 *    Returns: true if succesful connection, false if there was an error or the IP is not listed
 *
 *******************************************************************************************/
bool TCPConn::accept_conn(int server)
{
    // Accept Client
    struct sockaddr_in client_addr;
    socklen_t addrsize = sizeof(client_addr);
    my_sock = accept(server, (struct sockaddr *) &client_addr, &addrsize );

    if(my_sock < 0)
        return false;

    // Check if ip is whitelisted
    std::ifstream whitelist("whitelist");
    std::string read_addr;
    // Ip populated from client address to readable form
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
    
    bool white_ip = false;
    // Loop through file to check for IP of client
    while(std::getline(whitelist, read_addr))
    {
        if(read_addr == std::string(ip))
        {
            std::cout << "White IP!\n";
            white_ip = true;
            ip_address = std::string(ip);
        }

    }
    
    // Log events in server log
    std::stringstream log_txt;
    if(!white_ip)
    {
        sendText("Please connect from an allowed device!\n");
        log_txt << "Unlisted IP connection.\n";
        disconnect();
    }else {
        sendText("Username: ");
        log_txt << "Whitelisted IP connection\n";
    }
    log_txt << "IP Address: " << std::string(ip) << "\n";
    log(log_txt.str());
    whitelist.close();

    mode = mode_type::usrname;
    return true;
}


/*******************************************************************************************
 *  getSocket - returns the socket this TCPConn object uses
 *
 *    Params:  
 *
 *    Returns: socket
 *
 *******************************************************************************************/
int TCPConn::getSocket()
{
    return my_sock;
}

/*******************************************************************************************
 *  handleConnection - reads the message available on the socket and deals with it according
 *                      to the current mode
 *
 *    Params:  
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::handleConnection()
{
    char msg[20];
    int msg_len;
    msg_len = recv(my_sock, msg, 20, 0);

    std::stringstream log_txt;

    // If we received a 0, the connection closed
    if( msg_len == 0 ) 
    {
        std::cout << "Client has disconnected automatically\n";
        disconnect();
        log_txt << "User Disconnected\n";
        log_txt << "IP Address: " << ip_address << "\n";
        log_txt << "Username: " << msg << "\n";   
        log(log_txt.str());
        return;
    } else if(msg_len < 0)
    {
        // Recoverable: not uncommon for it to have a receive error
        std::cout << "Recieve Error!";
    }

    // Add a null operator to the end of the message
    msg[msg_len] = '\0';

    // Conver the char array to string for security and ease of use
    std::string input(msg, strlen(msg));
    switch (mode)
    {
        case mode_type::usrname:
            if(pwdMgr->checkUser(msg))
            {
                sendText("Password: ");
                mode = mode_type::psswd;
                username = input;
            } else 
            {
                sendText("Username not found. Diconnecting\n");
                disconnect();
                log_txt << "Username not found\n";
                log_txt << "IP Address: " << ip_address << "\n";
                log_txt << "Username: " << msg << "\n";   
                log(log_txt.str());
            }
            break;
        case mode_type::psswd:
            std::cout << "\nChecking Password\n";
            if(pwdMgr->checkPasswd(username.c_str(), msg))
            {
                sendMenu();
                mode = mode_type::menu_choice;
                pwd_attempts = 0;
                log_txt << "Succesful Login\n";
                log_txt << "IP Address: " << ip_address << "\n";
                log_txt << "Username: " << username << "\n";   
                log(log_txt.str());
            } else 
            {
                if(pwd_attempts == 0)
                {
                    sendText("Wrong password, try again.\nPassword: ");
                    pwd_attempts += 1;
                } else if(pwd_attempts > 0)
                {
                    sendText("Password was incorrect twice. Disconnecting\n");
                    disconnect();
                    log_txt << "Incorrect Password Attempts\n";
                    log_txt << "IP Address: " << ip_address << "\n";
                    log_txt << "Username: " << username << "\n";   
                    log(log_txt.str());
                }
            }
            break;
        case mode_type::psswd_chng:
            if(pwd_attempts == 2) {
                if(pwdMgr->changePasswd(username.c_str(), msg))
                {
                    mode = mode_type::menu_choice;
                    sendText("Password Changed!\n\n");
                    pwd_attempts = 0;
                } else
                {
                    mode = mode_type::menu_choice;
                    sendText("Probblem changing password.\n\n");
                    pwd_attempts = 0;
                }

            } else if(pwdMgr->checkPasswd(username.c_str(), msg))
            {
                if(pwd_attempts == 0)
                {
                    sendText("Please Enter Your Password a Second Time: ");
                    pwd_attempts += 1;
                } else if(pwd_attempts == 1) {
                    sendText("Please enter your new password: ");
                    pwd_attempts += 1;
                }
            } else
            {
                sendText("Wrong Password Entered!\n\nMenu Choice: ");
                mode = mode_type::menu_choice;
                pwd_attempts = 0;
            }
            break;
        case mode_type::menu_choice:
            handleMenu(input);
            break;
        case mode_type::add_usr:
            addUser(input);
            break;
        default:
            sendText("Unrecognized error, try again!\n");
    }

}

/*******************************************************************************************
 *  sendText - sends a message to the connected client
 *
 *    Params:  msg - messageto send
 *
 *    Returns: number of bytes sent
 *
 *******************************************************************************************/
int TCPConn::sendText(const char *msg)
{
    // std::cout << "Sending msg\n";

    int bytes_sent = 0, msg_len = 1, total_sent = 0;
    // Make a strstream so it's easier to append facts
    std::stringstream sendmsg;
    sendmsg << msg;
    // Check if the facts should be included
    if(cats) { sendmsg << "Cat Fact: " << cat_facts.at(rand() % cat_facts.size()) << "\n";}
    if(dogs) {sendmsg << "Dog Fact: " << dog_facts.at(rand() % dog_facts.size())  << "\n";}
    if(elephants) { sendmsg << "Elephant Fact: " <<  elephant_facts.at(rand() % elephant_facts.size()) << "\n"; }

    if(mode == menu_choice) {sendmsg << "Menu Choice: ";}

    msg_len = strlen(sendmsg.str().c_str());
    while(total_sent < msg_len)
    {
        // Keeps sending the string until the whole message arrives
        bytes_sent = send(my_sock, sendmsg.str().substr(bytes_sent, msg_len - total_sent).c_str(), msg_len - total_sent, 0);
        if(bytes_sent == -1)
        {
            std::cout << "Send Error!\n";
            return -1;    
        }

        total_sent += bytes_sent;
    }
    std::cout << "Sent: " << total_sent << " bytes" << "\t Msg Len: " << msg_len << "\n";
    // std::cout << "Message Sent: " << sendmsg.str();
    return bytes_sent;
}

/*******************************************************************************************
 *  sendMenu - arranges a string to display the menu to the user
 *
 *    Params:
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::sendMenu()
{
    std::stringstream menu_str;
    menu_str << "COMMAND MENU\n";
    for(auto const& [key, val] : menu_def)
    {
        menu_str << key << ":\t" << val << "\n";
    }
    menu_str << "Menu Choice: ";

    sendText(menu_str.str().c_str());
}

/*******************************************************************************************
 *  disconnect - disconnect socket from client
 *
 *    Params:
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::disconnect()
{
    std::cout << "Disconnecting from client...\n";
    close(my_sock);
    connected = false;
}

/*******************************************************************************************
 *  addUser - arranges a string to display the menu to the user
 *
 *    Params: data - username or password 
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::addUser(std::string data)
{
    if (pwdMgr->checkUser(data.c_str()))
   {
        mode = menu_choice; 
        sendText("That user already has an account.");
   } else
   {
       if(pwd_attempts == 0)
       {
           sendText("\nAdding user\nNew Password: ");
           pwd_attempts += 1;
           new_usr = data;
       } else if(pwd_attempts == 1)
       {
            sendText("\nEnter the password again: ");
            new_pass = data;
            pwd_attempts += 1;
       } else if(pwd_attempts == 2)
       {
           if(data == new_pass)
           {
               pwdMgr->addUser(new_usr.c_str(), data.c_str());
               mode = menu_choice;
               sendText("New user added!\n\n");
               pwd_attempts = 0;
           } else 
           {
               pwd_attempts = 1;
               sendText("Passwords must match. Try again.\n\nPassword: ");
           }
       }
        
   }

}

/*******************************************************************************************
 *  handleMenu - handle the cases for the different menu options
 *
 *    Params: input - user's menu choice
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::handleMenu(const std::string& input)
{
    // Set default state to unknown
    cmd_type cmd = cmd_type::unkown;
    // Loop through our cmd_table to find which command the client sent
    for(auto const& [key, val] : cmd_table)
    {
        // std::cout << "Key: " << key << "\tMsg: " << msg_str << "\n";
    if(key == input) 
    {
        //    std::cout << "Cmd = " << val << "\n";
        cmd = val;
        }
    }
    std::stringstream log_txt;
    switch(cmd)
    {
        case cmd_type::greeting:
            sendText("WHAT IS UP, Welcome to the Server. I hope you will have as much fund as we do.\n");
            break;
        case cmd_type::menu:
            sendMenu();
            break;
        case cmd_type::exit:
            log_txt << "User Disconnected\n";
            log_txt << "IP Address: " << ip_address << "\n";
            log_txt << "Username: " << username << "\n";   
            log(log_txt.str());
            disconnect();
            break;
        case cmd_type::change_psswd:
            mode = mode_type::psswd_chng;
            sendText("Password: ");
            break;
        case cmd_type::opt1:
            cats = true;
            sendText("Wow! You have signed up for cat facts (provided by factretriever.com). You will receive a cat fact after each command!\nHere is your first cat fact! I hope youre excited, because we are!\n");
            break;
        case cmd_type::opt2:
            dogs = true;
            sendText("Wow! You have signed up for dog facts (provided by factretriever.com). You will receive a dog fact after each command!\nHere is your first dog fact! I hope you're excited, because we are!\n");
            break;
        case cmd_type::opt3:
            elephants = true;
            sendText("Wow! You have signed up for elephant facts (provided by factretriever.com). You will receive a elephant fact after each command!\nHere is your first elephant fact! I hope youre excited, because we are!\n");
            break;
        case cmd_type::opt4:
            cats = false;
            dogs = false;
            elephants = false;
            sendText("You've cancelled all of your facts!\n");
            break;
        case cmd_type::opt5:
            cats = false;
            dogs = false;
            elephants = false;
            mode = mode_type::add_usr;
            sendText("Username: ");
            break;
        default:
            sendText("That didn't seem to be on the Menu! Take a gander at what we sent earlier and get back to me.\n");
            break;
    }

}

/*******************************************************************************************
 *  isConnected - tells whether the server is connected to a client
 *
 *    Params:
 *
 *    Returns: a bool indicating the state of the connection
 *
 *******************************************************************************************/
bool TCPConn::isConnected()
{
    return connected;
}

/*******************************************************************************************
 *  log - records info for th eserver
 *
 *    Params: information to record
 *
 *    Returns: 
 *
 *******************************************************************************************/
void TCPConn::log(const std::string& input)
{
    // Time and datestamp found on https://www.tutorialspoint.com/cplusplus/cpp_date_time.htm
    std::fstream log_file("server.log", std::ios_base::app);
    time_t now = time(0);
    tm *ltime = localtime(&now);
    log_file << "--------------------------------------" << "\n";
    log_file << "Time: " << ltime->tm_hour << ":";
    log_file << ltime->tm_min << ":" << ltime->tm_sec << "\n";
    log_file << "Date: " << 1900 + ltime->tm_year << " ";
    log_file << 1 + ltime->tm_mon << " " << ltime->tm_mday << "\n";
    log_file << input;
    log_file.flush();
    log_file.close();
}

