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
- Support replay multi pcap at the same time

## Features

- Work on both client and server ends, simulate the real environment
- Support adjust speed rate and quick mode by set with `--speed [INT]`and  `--quick`

## Usage

Deploy on server
```
pcapreplay.py --listen -p 6324
```
Then delploy on client and connect to server, and select which pcap file you want to replay
```
pcapreplay.py -f [pcapfile] -t 192.168.1.24 -p 6324
```
Besides, you can  the speed rate or use quick mode to send all the packet immediately. 

- How client works

  ```
  root@kali:~# python3 pcapreplay.py -t 10.100.1.30 -f telnet_microsoft.pcap -v -p 6325
  run as client
  [INFO] Try connecting to 10.100.1.30:6325
  [INFO] Success connecting to server, start sync pcap file
  [INFO] Try sending pcap file to server
  [INFO] Send telnet_microsoft.pcap.gz
  [INFO] Send file complete
  [INFO] Start send packet
  I:1T:1e-05 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet S
  I:2T:0.090384 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 SA
  pcapreplay.py:375: DeprecationWarning: an integer is required (got type decimal.Decimal).  Implicit conversion to integers using __int__ is deprecated, and may be removed in a future version of Python.
    time.sleep(delta)
  I:3T:0.090915 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet A
  I:4T:0.156529 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:5T:0.156947 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:6T:0.229954 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:7T:0.230467 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:8T:0.301207 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:9T:0.301644 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:10T:0.373422 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:11T:0.373874 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:12T:0.452399 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:13T:0.452845 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:14T:0.538246 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:15T:0.545968 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:16T:0.628641 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:17T:0.629748 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:18T:0.715245 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:19T:0.715713 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:20T:0.808539 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:21T:0.808978 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet FA
  I:22T:0.876498 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:23T:0.916494 <== Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 FA / Padding
  I:24T:0.917867 ==> Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet A
  [INFO] Send all packets finished, connection will be closed
  [INFO] Exit
  [INFO] Server wiil continue listening on port 6325
  ```

  ![demo_client](https://github.com/litheory/PcapReplayer/blob/main/demo_client.png)

- How server works

  ```
  test@test-virtual-machine:~$ sudo python3 pcapreplay.py --listen -v -p 6325
  [INFO] Listening on 0.0.0.0:6325
  [INFO] Accept connection from 10.100.1.31:43564
  [INFO] Try receiving pcap file from client
  100% |###############################################| Elapsed Time: 0:00:00   3.0 MiB/s
  [INFO] Valid file md5
  [INFO] RCSC: receive file success
  telnet_microsoft.pcap
  [INFO] Start send packet
  I:1T:0.11084 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet S
  I:2T:0.111229 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 SA
  I:3T:0.173398 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet A
  I:4T:0.173719 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:5T:0.241681 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:6T:0.242028 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:7T:0.317422 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:8T:0.31778 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:9T:0.394335 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:10T:0.394762 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:11T:0.461862 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:12T:0.462164 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw / Padding
  I:13T:0.549576 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:14T:0.550032 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:15T:0.633678 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:16T:0.633985 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:17T:0.725374 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:18T:0.72568 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:19T:0.813497 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet PA / Raw
  I:20T:0.813863 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 PA / Raw
  I:21T:0.889676 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet FA
  I:22T:0.89002 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 A / Padding
  I:23T:0.929229 ==> Ether / IP / TCP 59.28.233.196:telnet > 192.200.41.10:62852 FA / Padding
  I:24T:1.009487 <== Ether / IP / TCP 192.200.41.10:62852 > 59.28.233.196:telnet A
  [INFO] Send all packets finished, connection will be closed
  [INFO] Exit
  [INFO] Server wiil continue listening on port 6325
  
  ```

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

