from socket import *
from threading import Thread
import pdb
import pickle
import ast
import random
import argparse
import os
from subprocess import Popen, PIPE
import hashlib

# command-line encrypt and decrypt demo:
# echo "secret message" | openssl rsautl -encrypt -pubin -inkey server_pub.pem | openssl rsautl -decrypt -inkey server_pri.pem

# generate public and private key file:
# prefix=name
# openssl genrsa -out "${prefix}_pri.pem" 2048
# openssl rsa -in "${prefix}_pri.pem" -outform PEM -pubout -out "${prefix}_pub.pem"

# when executing remember to terminate clients first
# otherwise the server socket will have a TIME_WAIT for about 30 seconds while it
# cleans up the connection

def auth(username, password):
    address = str(int(get_xor(username, password)[0:2], 16))
    value = hashlib.sha256(password.encode()).hexdigest()
    p = Popen(['./auth.sh', address, value], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode().strip()
    return out

def update(username, password):
    address = str(int(get_xor(username, password)[0:2], 16))
    value = hashlib.sha256(password.encode()).hexdigest()    
    p = Popen(['./update.sh', address, value], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode().strip()
    return out

def get_xor(str1, str2):
    num = max(len(str1), len(str2))
    result = ""
    i = 0
    ndx1 = 0
    ndx2 = 0
    while(i < num):
        if(ndx1 == len(str1)):
            ndx1 = 0
        if(ndx2 == len(str2)):
            ndx2 = 0
        x1 = ord(str1[ndx1])
        x2 = ord(str2[ndx2])
        temp = hex(x1 ^ x2)[2:]
        if(len(temp) == 1):
            temp = '0' + temp
        result += temp
        ndx1 += 1
        ndx2 += 1
        i += 1
    return result

def encrypt(client_name, plaintext):
    # need single quotes to avoid expansion in bash
    # use bash to encrypt, convert binary output to hex
    command = f"echo -n '{plaintext}' | "
    command += f"openssl rsautl -encrypt -pubin -inkey {client_name}_pub.pem | "
    command += r"xxd -u -p | tr -d '\n'"
    stream = os.popen(command)
    cyphertext = stream.read()
    return cyphertext

def decrypt(cyphertext):
    # need single quotes to avoid expansion in bash
    # use bash to convert hex to raw binary, decrypt this binary into plaintext
    command = f"echo -n '{cyphertext}' | "
    command += "xxd -r -p | "
    command += "openssl rsautl -decrypt -inkey server_pri.pem"
    stream = os.popen(command)
    plaintext = stream.read()
    return plaintext

def send_to_client(client_socket, client_name, message, generator, do_encrypt):
    if(do_encrypt):
        message = encrypt(client_name, message)
    client_socket.send((message + "\n").encode())
    try:
        response = generator.__next__()
    except:
        # if no response then continue anyway
        response = ""
    if(do_encrypt and len(response) > 0):
        response = decrypt(response)
    return response

def readLines(sock, recv_buffer = 1024, delim='\n'):
    buffer = ''
    data = True

    while data:
        try:
            data = sock.recv(recv_buffer)
        except timeout:
            print('User inactive, closing connection')
            return
        except ConnectionResetError:
            print('Client closed connection')
            return
        except KeyboardInterrupt:
            print('Process ending')
      
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            yield line
    return

def client_handler(client_socket, client_ip, client_port, do_encrypt):
    print(f'New Connection from {client_ip}:{client_port}')

    g = readLines(client_socket)

    in_msg = g.__next__()
    if(do_encrypt):
        in_msg = decrypt(in_msg)
    client_name = in_msg[0:in_msg.find(" ")]
    password = in_msg[in_msg.find(" "):in_msg.find(":")]
    command = in_msg[in_msg.find(":")+2:]
    if(command == "get secret"):
        # check database
        if(auth(client_name, password) == 'true'):
            with open('secret.txt') as f:
                secret = f.read()
                send_to_client(client_socket, client_name, f"authentication success, secret is: {secret}", g, do_encrypt)
        else:
            send_to_client(client_socket, client_name, "authentication failure, please reconnect and enroll", g, do_encrypt)
    elif(command == "enroll"):
        # update database
        update(client_name, password)
        send_to_client(client_socket, client_name, "enrollment success", g, do_encrypt)
        return
    else:
        send_to_client(client_socket, client_name, "unknown query", g, do_encrypt)
    client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The server PUF communicator")
    parser.add_argument("port", type=int,
                        help="tcp port number, use 0 to any available port")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true",
                        help="set this option to encrypt all traffic")
    args = parser.parse_args()
    
    print("Server is running...")
    tcp_socket = socket(AF_INET, SOCK_STREAM)
    tcp_socket.bind(('', args.port)) # bound to any IP address, any port
    tcp_port = tcp_socket.getsockname()[1]
    
    print("TCP socket has port number: " + str(tcp_port))
    try:
        while True:
            tcp_socket.listen(0)
            client_socket, client_info = tcp_socket.accept()
            client_ip = client_info[0]
            client_port = client_info[1]
            Thread(target=client_handler,
                   args=(client_socket, client_ip, client_port, args.encrypt)).start()
    except KeyboardInterrupt:
        tcp_socket.close()
