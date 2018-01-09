#include "User.h"
#include <iostream>
#include <boost/asio.hpp>

using namespace std;

User::User(){
    cout << "===============================================" << endl;
    cout << "Welcome to Alan and Eric's netfilter project (enter 'help' for options)" << endl;
    cout << "===============================================" << endl;
}

User::~User(){
    cout << "\n";
    cout << "===============================================" << endl;
    cout << "Goodbye! " << endl;
    cout << "===============================================" << endl;
}

void User::start(){
    string commandStr;
    cout << "Enter a command: ";
    getline(cin, commandStr);

    //Processes the commands until prompted to exit
    while (commandStr != "exit"){
        if (commandStr == "block") goToBlock();
        else if (commandStr == "monitor") goToMonitor();
        else if (commandStr == "status") printStatus();
        else if (commandStr == "help") printOptions();
        else cout << "Invalid command entered\n";
        cout << "Enter a command: ";
        getline(cin, commandStr);
    }
}

void User::printOptions() {
    cout << "Make sure you are running this program as root!\n";
    cout << "Here are your options:\n" << endl;
    cout << "block     blocks/unblocks addresses\n";
    cout << "monitor   monitor/stop monitoring addresses\n";
    cout << "status    view statistics about monitored addresses\n";
    cout << "help      open help menu\n";
    cout << "exit      close program\n" << endl;
}

void User::goToBlock(){
    string command, address;
    cout << "Do you want to block or unblock? (b/u): ";
    getline(cin, command);
    if (command == "b"){
        cout << "Block all addresses? (y/n): ";
        getline(cin, command);
        if (command == "y") blockAll();
        else if (command == "n"){
            cout << "What address do you want to block?: ";
            getline(cin, address);
            blockX(address);
        }
        else cout << "invalid command entered\n";
    }
    else if (command == "u"){
        cout << "Unblock all addresses? (y/n): ";
        getline(cin, command);
        if (command == "y") unblockAll();
        else if (command == "n"){
            cout << "What address do you want to unblock?: ";
            getline(cin, address);
            unblockX(address);
        }
        else cout << "invalid command entered\n";
    }
    else cout << "invalid command entered\n";
}

void User::goToMonitor(){
    string command, address;
    cout << "Do you want to monitor or unmonitor? (m/u): ";
    getline(cin, command);
    cout << "What address do you want to start/stop monitoring?: ";
    getline (cin, address);
    if (command == "m") monitorX(address);
    else if (command == "u") unmonitorX(address);
    else cout << "invalid command entered\n";
}

void User::printStatus(){
    //Writes a sufficiently large message to proc so that
    //the file is big enough to be overridden, so that
    //when proc is read from later the full message can
    //be transmitted
    string buffer(500, ' ');
    buffer.push_back('\n');
    write2Proc(buffer);
    //Wait for kernel module to write to msg before reading
    sleep(1);
    //read from proc file
    FILE *fp;
    fp = fopen("/proc/firewall_rules", "r");
    if (fp == NULL) cout << "Unable to read from proc\n";
    else{
        int c;
        while ( (c = fgetc(fp)) != EOF) {
            printf("%c",c);
        }
        fclose(fp);
    }
}

void User::blockX(std::string address){
    if (!isIP(address)){
        cout << "Not a valid IP\n";
        return;
    }
    address.insert(0, 1, 'b');
    write2Proc(address);
}

void User::unblockX(std::string address){
    if (!isIP(address)){
        cout << "Not a valid IP\n";
        return;
    }
    address.insert(0, 1, 'u');
    write2Proc(address);
}

void User::blockAll(){
    write2Proc("b");
}

void User::unblockAll(){
    write2Proc("u");
}

void User::monitorX(std::string address){
    if (!isIP(address)){
        cout << "Not a valid IP\n";
        return;
    }
    address.insert(0, 1, 'm');
    write2Proc(address);
}

void User::unmonitorX(std::string address){
    if (!isIP(address)){
        cout << "Not a valid IP\n";
        return;
    }
    address.insert(0, 1, 'n');
    write2Proc(address);
}

bool User::isIP(std::string address){
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(address, ec);
    return !ec;
}

void User::write2Proc(std::string data){
    FILE *fp;
    fp = fopen("/proc/firewall_rules", "w");
    if (fp == NULL){
        cout << errno << endl;
        cout << "Unable to write to proc\n";
    }
    else{
        fprintf(fp, "%s", data.c_str());
        fclose(fp);
    }
}
