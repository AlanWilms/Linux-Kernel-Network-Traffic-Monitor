#ifndef USER_H
#define USER_H

#include <string>

class User{
public:
    //Constructor
    User();

    //Destructor
    ~User();

    //Run the program
    void start();

private:

    //Prints out valid commands (help)
    void printOptions();

    //Redirects to correct blocking function
    void goToBlock();

    //Redirects to correct monitoring function
    void goToMonitor();

    //Prints statistics on addresses being monitored
    //How many packets have been blocked/received from each address
    void printStatus();

    //Blocks packets from address
    void blockX(std::string address);

    //Unblocks packets from address
    void unblockX(std::string address);

    //Blocks all packets
    void blockAll();

    //Unblocks all packets
    void unblockAll();

    //Monitors given address
    void monitorX(std::string address);

    //Stops monitoring given address
    void unmonitorX(std::string address);

    //checks whether or not string is an IP address
    bool isIP(std::string address);

    //Writes data to the created proc file
    void write2Proc(std::string data);

};

#endif //USER_H
