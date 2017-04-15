# chat_client.py
#python client.py -u Alice -p 1 -sip 127.0.0.1 -sp 3000
#python client.py -u Alice -sip 127.0.0.1 -sp 3000 -pp 9091
#python client.py -u Bob -sip 127.0.0.1 -sp 3000 -pp 9092

import sys
import socket
import select
import argparse
import json
import random
import threading
import Queue
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import pickle

class Message :
    def __init__(self,msg,iv,tag):
        
        self.msg = msg
        self.tag = tag
        self.iv = iv



backend = default_backend()




TGT = {}
PEER_LIST = {'Alice':('127.0.0.1', 9091),'Bob':('127.0.0.1', 9092)}
PEER_SOCKETS = {}
SOCKET_LIST =[]
RECV_BUFFER = 4096
HOST = ''
PORT = random.randint(0,65535)

MASTER_IV = os.urandom(12)
MASTER_PASSWORD = 'awesome'

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"awesome")
MASTER_HASH = digest.finalize()

MASTER_KEY = MASTER_HASH
#for testing P2P encryption
USER_LIST ={'Alice': {'password':'awesome','server_master_key':42,'IPaddr':'127.0.0.1','session_key':54784},
'Bob': {'password':'awesome','server_master_key':69,'IPaddr':'127.0.0.1','session_key':54784}}

def get_primes(n):
    numbers = set(range(n, 1, -1))
    primes = []
    while numbers:
        p = numbers.pop()
        primes.append(p)
        numbers.difference_update(set(range(p*2, n+1, p)))
    return primes

def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-u', required=True, dest='user', help="User to be logged into server")
    parser.add_argument('-p', required=True, dest='userPass', help="User password for server authentication")
    parser.add_argument('-sip', required=True, dest='server', help="IP address of the server")
    parser.add_argument('-sp', required=True, dest='port', type=int, help="port to connect to server")
    parser.add_argument('-pp', required=True, dest='send_port', type=int, help="port for listening socket, testing only")
    return parser.parse_args(arglist)

def read_stdin(input_queue):
    while True:
        input_queue.put(sys.stdin.readline())

def server_authentication(args):
    user = args.user
    server_address = args.server
    port = args.port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(2)

    # connect to remote server
    print 'connecting'
    try :
        server_socket.connect((server_address, port))
    except :
        print 'Unable to connect'
        sys.exit()

    
    packet = {args.user: {'IP ADDRESS' : PEER_LIST[args.user]}}


    first_packet = json.dumps(packet)
    server_socket.send(first_packet)
    SOCKET_LIST.append(server_socket)
    

    puz_num = int (server_socket.recv(RECV_BUFFER))


    ans_puz = len (get_primes(puz_num))

    

    encryptor = Cipher(
        algorithms.AES(MASTER_KEY),
        modes.GCM(MASTER_IV),
        backend=default_backend()
    ).encryptor()


    cipherpuzzle = encryptor.update(str(ans_puz)) + encryptor.finalize()
    tag = encryptor.tag

    

    aes_packet = {'solution' : cipherpuzzle, 'iv' : MASTER_IV, 'tag' : tag}

    aes_packet_pickle = pickle.dumps(aes_packet).encode('base64', 'strict')
    
    
    server_socket.send(aes_packet_pickle)

    
    PEER_SOCKETS['server'] = server_socket
    recv_tk_pickle = server_socket.recv(RECV_BUFFER)
    recv_tag = pickle.loads(server_socket.recv(RECV_BUFFER))

    decryptor = Cipher(
                    algorithms.AES(MASTER_KEY),
                    modes.GCM(MASTER_IV, recv_tag),
                    backend=default_backend()
                    ).decryptor()

    recv_tk_plaintext = decryptor.update(recv_tk_pickle) + decryptor.finalize()

    recv_tk = pickle.loads(recv_tk_plaintext)

    
    tgt = recv_tk['TGT']
    skey = recv_tk['sessionKey']
    
    
    print 'Connected to remote server. You can start sending messages'


def find_peer_from_server(args, peer_name):
    request = {'request': {'name':peer_name,'tgt':args.user,'nonce':random.randint(0,65535)}}
    packet = json.dumps(request)
    #encrypt()
    PEER_SOCKETS['server'].send(packet)


def connect_to_peer(name, addr):
    print 'connecting to peer'
    print name
    print addr
    print addr[0]
    print addr[1]



    new_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_peer_socket.settimeout(2)

    # connect to peer server
    try :
        new_peer_socket.connect((addr[0], addr[1]))
    except :
        print 'Unable to connect'
        sys.exit()

    SOCKET_LIST.append(new_peer_socket)
    PEER_SOCKETS[name] = new_peer_socket



# def encryption():
#     # cipher key
#     key = os.urandom(32)
#     #CBC initiation vector
#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
#     encryptor = cipher.encryptor()
#     decryptor = cipher.decryptor()
#     for chunk in iter(partial(inPlainfile.read, 1024), ''):
#           cipherText = encryptor.update(chunk)
#           outCipherfile.write(cipherText)
#         ct = '' + encryptor.finalize()

#     for chunk in iter(partial(inCipherfile.read, 1024), ''):
#           if chunk == '':
#             outPlainFile.write(decryptor.update(chunk) + decryptor.finalize())
#             break
#           plainText = decryptor.update(chunk)
#     pass


def chat_client(args):
    #for testing REMEMBER TO REMOVE
    PORT = args.send_port
    #PEER_LIST = {args.user: ('127.0.0.1', PORT)}
    #I don't know why I needed to declare this global, it suddenly stopped working until I did this
    global PEER_LIST
    #for self identification
    PEER_LIST[args.user] = ('127.0.0.1', PORT)

    #Exchange credentials from server
    server_authentication(args)

    #server socket so that client can receive messages directly from peers instead of routing through server
    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiving_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receiving_socket.bind((HOST, PORT))
    receiving_socket.listen(10)
    SOCKET_LIST.append(receiving_socket)

    #initial user prompt
    sys.stdout.write('[ME] >'); sys.stdout.flush()

    #threading so that user input is non blocking
    #terrifying, here there be dragons
    #unless you know what you're doing, don't fuck with this
    input_queue = Queue.Queue()
    input_thread = threading.Thread(target=read_stdin, args=(input_queue,))
    input_thread.daemon = True
    input_thread.start()
    while 1:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
        #print SOCKET_LIST


        for sock in ready_to_read:
            print "ya?"
            if sock == receiving_socket:
                print "got the listener"
                sockfd, addr = receiving_socket.accept()
                SOCKET_LIST.append(sockfd)
        # process data recieved from client,
            else:
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        #make titles for data packets for sorting and use
                        sys.stdout.write("\n")
                        # this may need to change
                        pack = json.loads(data)
                        # for key in pack:
                        #     if key == 'peer':
                                #PEER_LIST = pack[key]
                        #this is probably temporary
                        print PEER_LIST
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        sys.stdout.write('\n[ME] >'); sys.stdout.flush()
                    else:
                        # remove the socket that's broken
                        print "we killed the socket"
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                            # exception
                except Exception as inst:
                    print "we lost our shit"
                    print(type(inst))    # the exception instance
                    print(inst.args)     # arguments stored in .args
                    print(inst)          # __str__ allows args to be printed directly,
                                         # but may be overridden in exception subclasses


        if not input_queue.empty():
            msg = input_queue.get()
            #print msg
            if str(msg) == "list\n":
                #received list command
                print("received list command")
                print PEER_LIST
                sys.stdout.write('[ME] >'); sys.stdout.flush()
            elif str(msg[:4]) == "send":
                print("get send")
                sending = msg.split()
                for name in PEER_SOCKETS:
                    # print sending
                    # print sending[1]
                    packet = json.dumps({"origin": [args.user, PEER_LIST[args.user]], "message": sending[2]})
                    #print packet
                    if sending[1] == name:
                        print("received send command")
                        print "sending to existing peer"
                        PEER_SOCKETS[name].send(packet)
                else:
                    print "need to connect to new peer"
                    connection_fuel = find_peer_from_server(args, sending[1])
                    #connect_to_peer(name, PEER_LIST[name])
                    #PEER_SOCKETS[name].send(packet)
                sys.stdout.write('[ME] >'); sys.stdout.flush()
                    # else:
                    #     print "error, no such user"
                    #     sys.stdout.write('[ME] >'); sys.stdout.flush()


            else:
                print "did we hit?"
                #print("Unrecognized command")
                sys.stdout.write('[ME] >'); sys.stdout.flush()







if __name__ == "__main__":
    #user1$ python ChatClient.py -u Alice -sip server-ip -sp 9090

    args = arguments(sys.argv[1:])
    sys.exit(chat_client(args))
