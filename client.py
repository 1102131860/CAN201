# This is client.py
from server import *

# global variables
ip, port, id, file, total_thread = "127.0.0.1", 1379, "1202437", "", 8
start_time, stop_time = 0, 0

def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--server_ip", default='127.0.0.1', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind to localhost.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("--id", default='1202437', action='store', required=False, dest="id",
                       help="Your id. Default is 1202437.")
    parse.add_argument("--f", default='', action='store', required=False, dest="file",
                       help="File path. Default is empty(No file will be upload)")
    parse.add_argument("--thread", default='8', action='store', required=False, dest="total_thread",
                       help="The total number of thread. Default is 1")
    return parse.parse_args()

def get_authorization(clientSocket):
    """
    Send auth information and receive a TCP "packet" containning token
    :param clientSocket: the TCP clientSocket to send packet
    :return: Token or False
    """
    global id
    username = id
    password = hashlib.md5(username.encode()).hexdigest()
    json_data = {
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_OPERATION: OP_LOGIN,
        FIELD_TYPE: TYPE_AUTH,
        FIELD_USERNAME: username,
        FIELD_PASSWORD: password
    }
    packet = make_packet(json_data)
    clientSocket.send(packet)

    received_json_data, received_bin_data = get_tcp_packet(clientSocket)
    if FIELD_TOKEN not in received_json_data:
        print("Fail to get FILED_TOKEN!")
        return False
    user_str = f'{json_data[FIELD_USERNAME].replace(".", "_")}.' \
               f'{get_time_based_filename("login")}'
    md5_auth_str = hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest()
    if base64.b64encode(f'{user_str}.{md5_auth_str}'.encode()).decode() != received_json_data[FIELD_TOKEN]:
        print("Token is incorrect!")
        return False
    token = received_json_data[FIELD_TOKEN]
    print(f"The checked Token is {token}")
    return token

def uploading_file(clientSocket, token):
    """
    Get file uploading plan and dispense thread
    :param clientSocket:
    :param token:
    """
    global file, total_thread, start_time
    fhand = open(file, "rb")
    fhand = open(file, "rb")
    bin_data = fhand.read()
    size_file = len(bin_data)
    json_data = {
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_OPERATION: OP_SAVE,
        FIELD_TYPE: TYPE_FILE,
        FIELD_TOKEN: token,
        FIELD_KEY: file,
        FIELD_SIZE: size_file
    }
    packet = make_packet(json_data)
    clientSocket.send(packet)

    received_json_data, received_bin_data = get_tcp_packet(clientSocket)
    print(received_json_data)
    if FIELD_BLOCK_SIZE not in received_json_data:
        print(f"Please don't send file with same path: {file}")
        return
    key = received_json_data[FIELD_KEY]
    block_size = received_json_data[FIELD_BLOCK_SIZE]
    total_block = received_json_data[FIELD_TOTAL_BLOCK]

    # decompose bin_data
    blocks = []
    for block_index in range(total_block):
        start_index = block_size * block_index
        end_index = start_index + block_size if block_index != total_block - 1 else size_file
        blocks.append(bin_data[start_index:end_index])

    # dispense thread
    start_time = time.time()
    if total_block < total_thread:
        total_thread = total_block
    for i in range(total_thread):
        thread = Thread(target=uploading, args=(clientSocket, token, key, blocks, i))
        thread.start()
        thread.join()

def uploading(clientSocket, token, key, blocks, index):
    """
    Send message block by block
    :param clientSocket:
    :param token:
    :param key:
    :param blocks:
    :param index:
    """
    global total_thread, start_time, stop_time
    for block_index in range(index, len(blocks), total_thread):
        json_data = {
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_OPERATION: OP_UPLOAD,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token,
            FIELD_KEY: key,
            FIELD_BLOCK_INDEX: block_index
        }
        packet = make_packet(json_data, blocks[block_index])
        clientSocket.send(packet)

        received_json_data, received_bin_data = get_tcp_packet(clientSocket)
        print(received_json_data)
        if FIELD_MD5 in received_json_data:
            stop_time = time.time()
            consumed_time = round(stop_time - start_time, 4)
            print(f"Consumed_time for sending this file is {consumed_time} secs")

def main():
    global server_ip, port, id, file, total_thread
    parser = _argparse()
    ip, port, id, file, total_thread = parser.ip, int(parser.port), parser.id, parser.file, int(parser.total_thread)
    server_IP_port = (ip, port)
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(server_IP_port)

    token = get_authorization(clientSocket)
    if token is False:
        return

    uploading_file(clientSocket, token)

if __name__ == "__main__":
    main()
