#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import time
import re

from progressbar import *
import getopt
import gzip
import hashlib
import json
import random

import socket
from scapy.all import *
from scapy.utils import rdpcap

import threading
import subprocess


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# global parameter
debug = True
verbose = False
listen = False      # listen is server, not listen is client
target = ""
port = 6324
interface = ""
pcap_file = ""
# speed = 1
# protocol = ""

def info(str):
    print("[INFO] " + str)
def error(str):
    print("[ERROR] " + str)
def conn_error(str):
    global port
    print("[ERROR] " + str)
    print("")
    info("Continue listening on %d" %port)
    sys.exit(0)
def exit_error(str):
    print("[ERROR] " + str)
    sys.exit(0)

def debugger(str):
    global debug
    if debug == True:
        print("[DEBUG] " + str)
def verboser(str):
    global verbose
    if verbose == True:
        print(str)

def validate_ip(ip):
    compile_ip = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ip):
        return True 
    else:  
        return False    
def validate_port(port):
    if port < 0 or port > 65535:
        return False
    else:
        return True

# Block calculation
def get_file_md5(file_name):
    md5 = hashlib.md5()
    with open(file_name, 'rb') as file_obj:
        while True:
            data = file_obj.read(4096)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()

def zip_file(file_name):
    ziped_file = file_name + '.gz'
    # Zip pcap
    debugger("Zip %s into %s" %(pcap_file, ziped_file))
    zip_obj = gzip.GzipFile(filename = file_name, mode = "wb+", compresslevel = 9, fileobj = open(ziped_file, 'wb'))
    zip_obj.write(open(file_name, 'rb').read())
    zip_obj.close()
    return ziped_file
def unzip_file(file_name):
    pcap_file = os.path.splitext(file_name)[0]
    print(pcap_file)
    zip_obj = gzip.GzipFile(mode = "rb", fileobj = open(file_name, "rb"))
    open(pcap_file, "wb+").write(zip_obj.read())
    return pcap_file

def send_file(client):
    global pcap_file

    ziped_file = zip_file(pcap_file)

    # Convert the header to a string (json.dumps), and then pack the length of the string.
    # Send header length, then send header content, and finally replay content.
    # Header contents include file name, file information, header

    # file_index = 0
    debugger("Get file bytes size")
    filesize_bytes = os.path.getsize(ziped_file)  
    debugger("Get file md5")
    file_md5 = get_file_md5(ziped_file)
    debugger("Create header info")
    dirc = {
        # 'fileindex': file_index,
        'filename': ziped_file,
        'filesize_bytes': filesize_bytes,
        'md5': file_md5
    }
    # Convert dic to string
    debugger("Convert file dic to string")
    head_info = json.dumps(dirc)    
    print(head_info)
    head_info_len = struct.pack('i', len(head_info))
    # print(head_info_len)  

    # Send the length of head_info
    client.send(head_info_len)  
    client.send(head_info.encode('utf-8'))

    # Send file
    with open(ziped_file, 'rb') as fd:
        data = fd.read()
        client.send(data)

def receive_file(server):
    global pcap_file

    buffer_size = 1024
    # Firstly receive 6 byte header length
    # Decompress the header length, get the size of the header, receive the header, and deserialize (json.loads).
    # Finally receiving the file

    # Received header length
    debugger("Received header info")
    head_struct = server.recv(4)
    print(head_struct) 
    # debugger("Unpack header") 
    head_len = struct.unpack('i', head_struct)[0]
    # print(head_len)
    # debugger("Receive header dir")
    data = server.recv(head_len)
    head_dir = json.loads(data.decode('utf-8'))
    # file_index = head_dir['fileindex']
    filesize_b = head_dir['filesize_bytes']
    filename = head_dir['filename']
    md5 = head_dir['md5']  

    debugger("Receive full file")
    recv_len = 0  
    recv_file = b''

    with open(filename, 'wb+') as fd:
        # debugger("open %s" %filename)
        widgets = [Percentage(), ' ', Bar(), ' ', Timer(), ' ', FileTransferSpeed()]
        with ProgressBar(widgets=widgets, max_value=filesize_b) as bar:
            # debugger("Create progress bar")
            while recv_len < filesize_b:

                bar.update(recv_len)

                if filesize_b - recv_len > buffer_size:
                    recv_file = server.recv(buffer_size)
                    fd.write(recv_file)
                    recv_len += len(recv_file)
                else:
                    recv_file = server.recv(filesize_b - recv_len)
                    recv_len += len(recv_file)
                    fd.write(recv_file)

    return filename, md5

# sync pcap file between client and server
def sync_file(host):
    # listen is server, not listen is client
    global listen
    global pcap_file

    if not listen:
        client = host
        try:
            debugger("Try sending pcap file to server")
            send_file(client)
            info("Send file complete")
            # client.send("200 send file success".encode('utf-8'))
        except:
            client.send("400".encode('utf-8'))
            exit_error("400: send file failed")
    # server unzip file module
    else:
        server = host
        try:

            debugger("Try receiving pcap file from client")
            ziped_file, head_md5 = receive_file(server)

            debugger("Check if file md5 is accurate")
            file_md5 = get_file_md5(ziped_file)
            if file_md5 == head_md5:
                info("Valid file md5")
                server.send("202".encode('utf-8'))
                info("202: receive file success")
            else:
                exit_error("Invalid file md5! Failed to receive file")
                server.send("500".encode('utf-8'))
                conn_error("500: receive file error")
            
            debugger("Unzip pcap file")
            pcap_file = unzip_file(ziped_file)
            if os.path.exists(ziped_file):
                os.remove(ziped_file)
        except:
            server.send("500".encode('utf-8'))
            conn_error("500: receive file error")

# def load_pcap()

def run_as_server():
    global target
    global port

    # if no target is defined we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"
    elif not validate_ip(target):
        exit_error("Invalid IP address!")
    if not port:
        port = 6324
    elif not validate_port(port):
        exit_error("Invalid port!")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(100)
    info("Listening on %s:%d" %(target, port))

    while True:
        conn, addr = server.accept()
        info("Accept connection from %s:%d" %(addr[0], addr[1]))
        conn_thread = threading.Thread(target = conn_handler, args = (conn,))
        conn_thread.start()

def conn_handler(conn):
    conn.send("200".encode('utf-8'))
    info("200: connection accepted")
    while True:

        if not conn:
            info("%s:%d has disconnected" %(addr[0], addr[1]))
            break

        request = conn.recv(3).decode('utf-8')
        if request == "":
            conn_error("connection closed by peer")
        elif request == "100":
            debugger("CLIENT 100 => connection established")
            info("Receive pcap file from client")
            sync_file(conn)
        elif request == "400":
            conn_error("CLIENT 400 => send file failed")

def run_as_client():
    global target
    global port
    global pcap_file

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connet to our target host
        info("Try connecting to %s:%d" %(target, port))
        client.connect((target, port))

        while True:
            response = client.recv(3).decode('utf-8')
            if response == "":
                error("Connection closed by peer")
                client.close()
            elif response == "200":
                debugger("SERVER 200 => connection accepted")
                info("Success connecting to server, start sync pcap file")
                client.send("100".encode('utf-8'))
                info("100 connected established")
                # send file to server
                sync_file(client)
            elif response == "202":
                debugger("SERVER 202 => receive file success")
                if os.path.exists(pcap_file+'.gz'):
                    os.remove(pcap_file+'.gz')
            elif response == "500":
                exit_error("SERVER 500 => receive file failed")
            
    except socket.error as exc:
        # just catch generic errors
        error("Exception! Exiting.")
        error("Caught exception socket.error: %s" %exc)

        # teardown the connection
        client.close()

def usage():
    print("PcapReplayer v0.1 by Lithium")
    print("Usage:")
    print("SERVER: pcapreplay.py -i [interface] --listen -t [listen_target] -p [port]")
    print("CLIENT: pcapreplay.py -i [interface] -t [target] -p [port] -f [pcapfile]")
    print("-i --interface             - CLIENT Client to server traffic output interface")
    print(                             "SERVER Server to client traffic output interface")
    print(                             "Default use eth0")
    print("-f --file                  - CLIENT upon receiving connection upload a file and write to [target]")
    print("-l --listen                - SERVER listen on [host]:[port] for incoming connections")
    print("-t --target                - CLIENT connect to target host")
    print(                             "SERVER listening on this host, default on 0.0.0.0")
    print("-p --port                  - CLIENT connect to target port")
    print(                             "SERVER listen on this port")
    print(                             "Default use port 6324")
    print("-v --verbose               - Print decoded packets via tcpdump to STDOUT")
    print("-d --debug                 - Initiate with debugging mode")
    print("-h --help                  - Extended usage information passed thru pager")
    print("Run as SERVER: ")
    print("pcapreplay.py -i eth0 --listen -p 6324")
    print("Run as CLIENT:")
    print("pcapreplay.py -i eth0 -f [pcap_file] -t 192.168.1.24 -p 6324")
    sys.exit(0)

def main():
    global listen
    global target
    global port
    global pcap_file
    global interface
    global debug
    global verbose

    if not len(sys.argv[1:]):
        usage()
    # read the commandlien options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hldvt:p:i:f:", ["help", "listen", "debug", "verbose", "target", "port", "interface", "pacpfile"])
        for o,a in opts:
            if o in ("-h", "--help"):
                usage()
            elif o in ("-l", "--listen"):
                listen = True
            elif o in ("-t", "--target"):
                target = a
            elif o in ("-p", "--port"):
                port = int(a)
            elif o in ("-f", "--file"):
                pcap_file = a
            elif o in ("-i", "--interface"):
                interface = a
            elif o in ("-d", "--debug"):
                debug = True
            elif o in ("-v", "--verbose"):
                verbose = True
            else:
                assert False, "Unhandled Option"
    except getopt.GetoptError as err:
        print(str(err))
        usage()
    # we are going run as a client send data to server 
    if not listen > 0:
        debugger("check if %s:%d is a valid address" %(target, port))
        if not len(target):
            exit_error("Must select a target host!")
        elif not validate_ip(target):
            exit_error("Invalid IP address!")  
        if not port:
            port = 6324
            info("Default connect to remote port 6324")
        elif not validate_port(port):
            exit_error("Invalid port!")
        debugger("check if %s is a valid file" %pcap_file)
        if not len(pcap_file):
            exit_error("Must select a pcap/pcapng file!")
        elif not pcap_file.endswith('pcap') or pcap_file.endswith('pcapng'):
            exit_error("Wrong file type! Must select a pcap/pcapng file.")
        else:
            # check if pcap_file exists
            if os.path.exists(pcap_file):
                print("run as client")
                run_as_client()
            else:
                exit_error("%s does not exist." %pcap_file)
    # we are going to listen as a server
    if listen:
        run_as_server()

main()