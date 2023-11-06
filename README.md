# go-tcpkill
A tcpkill implementation in Go using [gopacket](https://github.com/gopacket/gopacket)


## What it does
[Tcpkill](https://linux.die.net/man/8/tcpkill) is a well-known tool part of the [Dsniff](https://linux.die.net/man/8/dsniff)
suite. It is used to terminate tcp connections between two hosts without having to control either party.

Tcpkill does this by injecting RST (reset) packets into the conversation that will trigger the closure
of a connection by the respective TCP implementation of the underlying operating system.

Usage of the tool can be classified as a MITM (man-in-the-middle) attack.

## Why use it?
The primary use case for tcpkill is to test how existing programs react to problems with the network.
Typically, it is tested if the program will successfully try to reconnect and / or write the appropriate error
messages. 

The benefit of using tcpkill is that connections can be closed **without having to close the programs that opened them**.

## How to use it
```shell
go-tcpkill -i <iface> '<filter>'
```
e.g.
```shell
go-tcpkill -i eth0 'host 123.123.123.123'
```
This will close all connections to and from ip 123.123.123.123

## Why reimplement Tcpkill in Go?
1. Fun ;)
2. I wanted to test the capabilities of the [gopacket library](https://github.com/gopacket/gopacket)
3. Tcpkill / Dsniff is not available on all distros and kind of abandoned now. Bringing it to the modern era and making it portable felt like a worthwhile effort.

## Acknowledgements
Tcpkill and Dsniff were originally written by [Dug Song](https://github.com/dugsong)