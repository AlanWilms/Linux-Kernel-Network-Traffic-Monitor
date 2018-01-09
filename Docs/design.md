# Design

Our goal is to build a kernel module that monitors network traffic. This module will allow users to specify things like “block all network traffic” and “print network traffic info." 

## Requirements and Implementaion

We will have two files: network.c and a makefile. The network.c uses netfilter hooks to implement the linux kernel module that does the actual network monitoring/logging/filtering. Furthermore, we will use a proc filesystem in order for the user to interact with and configure the module's functionality at runtime. Upon updating the specific file in /proc, the module should reread the data in the file and perform the appropriate filtering.

Specifically, the user-module interaction will allow for the following functionality:
* indicate all incoming or all outgoing traffic should be blocked or unblocked
* give specific addresses whose packets should be blocked or unblocked
* monitor (or quit monitoring) how many packets are received (and possibly blocked) from a specified address
* view the statistics about the addresses that are being monitored, specifically how many packets have been received (and possibly blocked) from the addresses that are being monitored.

As such, we will be having the following methods:
1. A main method that receives the user's inputs (via the proc file system) and calls the relevant methods
2. A method to parse the user's input and handle them appropriately
3. A method to filter all incoming and outgoing traffic
4. A method to filter all incoming outoing traffic to/from specific addresses
5. A method that records how many packets are received from a particular address
6. A method to print out the data in a readable format
7. A number of helper methods to reduce redundant code

## Testing and Integration

Our first step will be creating a "hello world" kernel module as demonstrated by http://www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/ and http://www.paulkiddie.com/2009/11/creating-a-netfilter-kernel-module-which-filters-udp-packets/. This will give us a foundation in testing insmod to add the kernel module. 

Most of our testing will be manual testing. Using the "dmesg" command, we will view our module's output and confirm the correctness of the output. By blocking a couple of address and comparing any differences in how many packets are received before or after this change, we can test our blocking. Additionally, comparing the ouput with the output of some built-in (for example Ethereal) allows us to verify the correctness of the entire project.
