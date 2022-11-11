# This is client.py
from server import *
import hashlib

period = f""

def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    return parse.parse_args()


def get_authorization(clientSocket):
    """
    Send auth information and receive a TCP "packet" containning token
    :param clientSocket: the TCP clientSocket to send packet
    :return: Token
    """
    USERNAME = "2033922"
    PASSWORD = hashlib.md5(USERNAME.encode()).hexdigest()

    # send auth information
    josn_data = {
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_OPERATION: OP_LOGIN,
        FIELD_TYPE: TYPE_AUTH,
        FIELD_USERNAME: USERNAME,
        FIELD_PASSWORD: PASSWORD
    }
    packet = make_packet(josn_data)
    clientSocket.send(packet)

    # receive packet containning token
    received_json_data, received_bin_data = get_tcp_packet(clientSocket)
    return received_json_data[FIELD_TOKEN] if FIELD_TOKEN in received_json_data else received_json_data

def get_uploading_plan(clientSocket, token, size_file):
    """
    Get file uploading plan and get the key
    :param clientSocket:
    :param token:
    :param size_file:
    :return: key, file_size, block_size, total_block, and so on
    """
    # send uploading application
    josn_data = {
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_OPERATION: OP_SAVE,
        FIELD_TYPE: TYPE_FILE,
        FIELD_TOKEN: token,
        FIELD_SIZE: size_file
    }
    packet = make_packet(josn_data)
    clientSocket.send(packet)

    # receive packet containning key
    received_json_data, received_bin_data = get_tcp_packet(clientSocket)
    return received_json_data

def uploading_file(clientSocket, token, key_block, bin_data):
    """
    Keeping sending block_size_binary_file_data untill get file_MD5
    :param clientSocket:
    :param token:
    :param key_block: key, file_size, block_size, total_block and so on
    :param bin_data: the binary data of the uploading files
    :return: file_MD5
    """
    global period
    starttime = time.time()
    block_index = 0
    key = key_block[FIELD_KEY]
    size_file = key_block[FIELD_SIZE]
    block_size = key_block[FIELD_BLOCK_SIZE]
    total_block = key_block[FIELD_TOTAL_BLOCK]

    while True:
        josn_data = {
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_OPERATION: OP_UPLOAD,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token,
            FIELD_KEY: key,
            FIELD_BLOCK_INDEX: block_index
        }

        start_index = block_size * block_index
        end_index = start_index + block_size if block_index != total_block - 1 else size_file
        block_bin_data = bin_data[start_index:end_index]

        # send joson_data and the block binary data of file
        packet = make_packet(josn_data, block_bin_data)
        clientSocket.send(packet)

        # receive packet from server and update block_index, key, check file_MD5 exists in packets
        received_json_data, received_bin_data = get_tcp_packet(clientSocket)
        block_index = received_json_data[FIELD_BLOCK_INDEX] + 1
        key = received_json_data[FIELD_KEY]
        if FIELD_MD5 in received_json_data:
            endtime = time.time()
            period = round(endtime - starttime, 4)
            return received_json_data[FIELD_MD5]

def main():
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    server_IP_port = (server_ip, int(server_port))
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(server_IP_port)

    # Firstly get token from server, token: bytes
    token = get_authorization(clientSocket)
    print(f"Token is {token}")

    fhand = open('picture.jpg','rb')
    bin_data = fhand.read()
    size_file = len(bin_data)

    # File uploading plan and get the key along with the requirements for files
    key_block = get_uploading_plan(clientSocket,token,size_file) # dict
    print(f"Key and block are {key_block}")

    # File uploading block by block and get file_MD5
    file_MD5 = uploading_file(clientSocket, token, key_block, bin_data)
    print(f"File_MD5 is {file_MD5} \nPeriod for sending this file is {period} secs")

if __name__ == "__main__":
    main()
