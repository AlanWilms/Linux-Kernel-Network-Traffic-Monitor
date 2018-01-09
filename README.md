# FinalProject: Network Firewall Module

Eric Zhuang and Alan Wilms
TR 1:10 - 2:25

https://github.com/CS3281-vu/spring-2017-project/blob/master/project-2-network-module.md

In this project, we will build a kernel module that monitors network traffic. This module will allow users to specify things like “block all network traffic” and “print network traffic info." We'll be using netfilter (www.netfilter.org), a software packet filtering framework. Netfilter will let the kernel module register callback functions with the network stack. Netfilter is the library used by software like iptables to implement firewalls.

## Components:

* [Design Document](./Docs/design.md)
* [Presentation](./Docs/ZhuangWilmsOS.pptx)
* [Report](./Docs/report.md)

* [Netfilter Module Code](./netfilter.c)
* [UI Code](./UI/User.h)

## Instructions for running program:

* make

* sudo insmod netfilter.ko

* sudo UI/cmake-build-debug/UI

*After finished*

* sudo rmmod netfilter.ko



