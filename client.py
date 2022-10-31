# This is client.py
from socket import *
from server import *
import argparse
import time

def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    return parse.parse_args()

def main():
    print(OP_SAVE)
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    server_IP_port = (server_ip, int(server_port))
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(server_IP_port)



if __name__ == "__main__":
    main()
