# Pcap Replayer
A tool used for editing and replaying network traffic, which was previously captured by tools like tcpdump and 	Wireshark, between client and server. It allows you to replay the traffic back onto the network and through other 	devices such as firewalls. Moreover, it supports adjusting the speed rate so you can replay slow and distributed brute 	force attck traffic.
# Usage
Start the server
```
pcapreplay.py -i eth0 --listen -p 6324
```
then use client connect to server and transport the pcap file to remote end
```
pcapreplay.py -i eth0 -f [pcapfile] -t 192.168.1.24 -p 6324
```
## Help doc
```
[SERVER]: pcapreplay.py -i [interface] --listen -p [port]

[SERVER]: pcapreplay.py -i [interface] --listen -p [port]

-i --interface             - [CLIENT] Client to server traffic output interface
                             [SERVER] Server to client traffic output interface
                             
-f --file                  - [CLIENT] upon receiving connection upload a file and write to [target]

-l --listen                - [SERVER] listen on [host]:[port] for incoming connections

-p --port                  - [CLIENT] connect to target port
                             [SERVER] listen on this port

-v --verbose               - Print decoded packets via tcpdump to STDOUT

-h --help                  - extended usage information passed thru pager                         
```
