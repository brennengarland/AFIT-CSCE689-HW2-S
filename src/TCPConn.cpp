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

TCPConn::TCPConn() {}

bool TCPConn::accept_conn(int server)
{
    // std::cout << "Entered accept\n";
    // Random seed for our options
    srand(time(0));

    pwdMgr = new PasswdMgr("user_pass.txt");

    struct sockaddr_in client_addr;
    socklen_t addrsize = sizeof(client_addr);
    my_sock = accept(server, (struct sockaddr *) &client_addr, &addrsize );

    if(my_sock < 0){ return false;}

    std::ifstream whitelist("whitelist.txt");
    std::string read_addr;
    char ip[INET_ADDRSTRLEN];
    bool white_ip = false;
    inet_ntop(AF_INET,&(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
    while(std::getline(whitelist, read_addr))
    {
        if(read_addr == std::string(ip))
        {
            std::cout << "White IP!\n";
            white_ip = true;
            ip_address = std::string(ip);
        }

    }
    
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
    mode = mode_type::usrname;
    return white_ip;
}

int TCPConn::getSocket()
{
    return my_sock;
}

void TCPConn::handleConnection()
{
    char msg[20];
    int msg_len;
    msg_len = recv(my_sock, msg, 20, 0);
    // If we received a 0, the connection closed
    if( msg_len == 0 ) 
    {
        // std::cout << "Client has disconnected automatically\n";
        disconnect();
    } else if(msg_len < 0)
    {
        // Recoverable: not uncommon for it to have a receive error
        std::cout << "Recieve Error!";
    }

    // Add a null operator to the end of the message
    msg[msg_len] = '\0';
    // std::cout << "Received Message: " << msg << "\n";
    // std::cout << "Bytes received: " << strlen(msg) << "\n";

    // Conver to the char array to string for security and ease of use
    std::string input(msg, strlen(msg));
    std::stringstream log_txt;
    switch (mode)
    {
        case mode_type::usrname:
            // handleUser(input);
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
            
            if(pwdMgr->checkPasswd(username.c_str(), msg))
            {
                sendMenu();
                mode = mode_type::menu_choice;
                pwd_attempts = 0;
                log_txt << "Succesful Login\n";
                log_txt << "IP Address: " << ip_address << "\n";
                log_txt << "Username: " << msg << "\n";   
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
        case mode_type::menu_choice:
            handleMenu(input);
            break;
        default:
            sendText("Unrecognized error, try again!\n");
    }

}

int TCPConn::sendText(const char *msg)
{
    // std::cout << "Sending msg\n";

    int bytes_sent = 0, msg_len = 1, total_sent = 0;
    // Make a strstream so it's easier to append facts
    std::stringstream sendmsg;
    sendmsg << msg;
    // Check if the facts should be included
    if(cats) { sendmsg << "Cat Fact: " << cat_facts.at(rand() % std::size(cat_facts)) << "\n";}
    if(dogs) {sendmsg << "Dog Fact: " << dog_facts.at(rand() % std::size(dog_facts))  << "\n";}
    if(elephants) { sendmsg << "Elephant Fact: " <<  elephant_facts.at(rand() % std::size(elephant_facts)) << "\n"; }
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

void TCPConn::disconnect()
{
    shutdown(my_sock,2);
    connected = false;
}

std::vector<std::string> TCPConn::parseCmd(const std::string msg)
{
    std::vector<std::string> cmds;
    std::stringstream cmd;
    // std::cout << "Character sequence start: \n";
    for(auto charc : msg)
    {
        // std::cout << charc << "\n";
        if(charc == '\n')
        {
            cmds.push_back(cmd.str());
            cmd.str("");
            cmd.clear();
        }
        cmd << charc;
    }
    // std::cout << "Commands: \n";
    // for(auto command : cmds)
    // {
    //     std::cout << command << "\n";
    // }

    return cmds;
}

void TCPConn::addUser(std::string data)
{
    std::cout << "Status Type: " << mode << std::endl;
    if(mode == mode_type::menu_choice)
    {
        sendText("Please enter the username for the user you would like to add.\n");
    } else if(mode == mode_type::usrname)
    {   
        sendText("Please enter password.\n");
        username = data;
    } else if(mode == mode_type::psswd)
    {
        data = hash(data);
        std::cout << "Storing data!";
        std::ofstream user_pass("user_info.txt", std::ios_base::app);

        user_pass << username << "," << data << "\n";

        user_pass.close();
        sendText("User and Password saved!");
    }

}


std::string TCPConn::hash(const std::string& password)
{
    std::cout << "Hashing...\n";
    return password;
}

bool TCPConn::checkUser(const std::string& username)
{
    bool auth = false;
    std::ifstream user("user_info.txt");
    std::stringstream line;
    // std::string username;
    std::string password;
    while(user.good())
    {
    //    getline(user, username);
       std::cout << username;

    }

}

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
    switch(cmd)
    {
        case cmd_type::greeting:
            sendText("WHAT IS UP, Welcome to the Server. I hope you will have as much fund as we do.\n");
            break;
        case cmd_type::menu:
            sendMenu();
            break;
        case cmd_type::exit:
            disconnect();
            break;
        case cmd_type::change_psswd:
            sendText("Changing Password...\n");
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
            addUser();
            mode = mode_type::usrname;
            break;
        default:
            sendText("That didn't seem to be on the Menu! Take a gander at what we sent earlier and get back to me.\n");
            break;
    }

}

bool TCPConn::isConnected()
{
    return connected;
}

void TCPConn::handleUser(const std::string& input)
{
    std::ifstream user_pass("user_pass.txt");   
    std::string in_name, in_psswd;
    bool user_found = false;
    while(std::getline(user_pass, in_name, ','))
    {
        std::getline(user_pass, in_psswd);
        std::cout << "Client Username: " << input << "\n";
        std::cout << "Looped Username: " << in_name << "\n";
        if(in_name == input)
        {
            std::cout << "Found username!\n";
            username = in_name;
            password = in_psswd;
            user_found = true;
        }
    }

    if(user_found == false)
    {
        sendText("Could not find your username!\n");
        disconnect();
    } else {
        sendText("Password: ");
    }
}

void TCPConn::handlePsswd(const std::string& input)
{
    if(pwd_attempts == 0)
    {
        // argon2_sal
    }
}


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
}

