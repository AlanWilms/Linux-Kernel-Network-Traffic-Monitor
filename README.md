Network Firewall Module

Co-authored by [Eric Zhuang](https://github.com/ezhuang13)

The project is a kernel module that monitors network traffic. This module will allow users to specify things like “block all network traffic” and “print network traffic info." We'll use netfilter (www.netfilter.org), a software packet filtering framework. Netfilter will let the kernel module register callback functions with the network stack. Netfilter is the library used by software like iptables to implement firewalls.

## Components:

* [Design Document](./Docs/design.md)
* [Presentation](./Docs/ZhuangWilmsOS.pptx)
* [Report](./Docs/report.md)

* [Netfilter Module Code](./netfilter.c)
* [UI Code](./UI/User.h)

## Instructions for running program:

```
make
sudo insmod netfilter.ko
sudo UI/cmake-build-debug/UI
sudo rmmod netfilter.ko
```
