# Pcap Replayer
Pcap Replayer is a tool used for editing and replaying network traffic between client and server for testing your Internet devices. It allows you to replay the traffic back onto the network and through other devices such as switches, routers, firewalls, NIDS and IPS's. It supports based on the packet timestamp so that you can test your devices’ performance on malicious traffic which rely on time-based features, such as slow and distributed brute force attck traffic.

## Installation

```
git clone https://github.com/litheory/PcapReplayer.git
cd PcapReplayer
pip install -r requirements
```
## Secnarios

This tool need deploy on both server-side and client-side, and parse your pcap file and replay back onto the network and through other devices, just like they are really connected and send packets to each other in realtime.

- Perfomance comprasion

A typical scenarios is to test your firewall’s or waf’s detection performance on malicious traffic, you can easily deploy this tool on your intranet client and server where the traffic can through in your device.

- Distributed stress testing
- Regression testing

## ToDo

- Support costum module
- Support loop replay

## Usage

Deploy on server
```
pcapreplay.py --listen -p 6324
```
Then delploy on client and connect to server, and select which pcap file you want to replay
```
pcapreplay.py -f [pcapfile] -t 192.168.1.24 -p 6324
```
Besides, you can adjust the speed

- How client works

  ![demo_client](https://github.com/litheory/PcapReplayer/blob/main/demo_client.png)

- How server works

  ![demo_client](https://github.com/litheory/PcapReplayer/blob/main/demo_server.png)

You can see the help doc by `-h`  or `--help`

```
SERVER: pcapreplay.py -i [interface] --listen -t [listen_target] -p [port]
CLIENT: pcapreplay.py -i [interface] -t [target] -p [port] -f [pcapfile]
-i --interface             - CLIENT Client to server traffic output interface
							 SERVER Server to client traffic output interface
Default use eth0
-f --file                  - [CLIENT] upon receiving connection upload a file and write to [target]
-l --listen                - [SERVER] listen on [host]:[port] for incoming connections
-t --target                - [CLIENT] connect to target host
							 [SERVER] listening on this host, default on 0.0.0.0
-p --port                  - [CLIENT] connect to target port
							 [SERVER] listen on this port
							 Default use port 6324
-v --verbose               - Print decoded packets via tcpdump to STDOUT
-d --debug                 - Initiate with debugging mode
-h --help                  - Extended usage information passed thru pager
Run as SERVER:
pcapreplay.py -i eth0 --listen -p 6324
Run as CLIENT:
pcapreplay.py -i eth0 -f [pcap_file] -t 192.168.1.24 -p 6324                   
```

