# chat_client.py
#python client.py -u Alice -p awesome -sip 127.0.0.1 -sp 3000

#python client.py -u Alice -sip 127.0.0.1 -sp 3000 -pp 9091
#python client.py -u Bob -sip 127.0.0.1 -sp 3000 -pp 9092

#python client.py -u Alice -p awesome -sip 127.0.0.1 -sp 3000 -pp 9091
#python client.py -u Bob -p awesome -sip 127.0.0.1 -sp 3000 -pp 9092


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

MESSAGE_QUEUE = []
Server_Nonce = 0
Peer_Nonce = 0
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
EX = 0XFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G =2

MASTER_IV = os.urandom(12)
MASTER_PASSWORD = 'awesome'

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"awesome")
MASTER_HASH = digest.finalize()

MASTER_KEY = MASTER_HASH

SESSION_KEY 
SESSION_IV = os.urandom(12)

#for testing P2P encryption
USER_LIST ={'Alice': {'password':'awesome','server_master_key':42,'IPaddr':'127.0.0.1','session_key':54784},
'Bob': {'password':'awesome','server_master_key':69,'IPaddr':'127.0.0.1','session_key':54784}}

def encryptor(key,iv,plaintext):
    
    
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    tag = encryptor.tag

    return key,iv,ciphertext,tag


def decryptor(key,iv,tag,ciphertext)
    
    decryptor = Cipher(
         algorithms.AES(key),
         modes.GCM(iv, tag),
         backend=default_backend()
    ).decryptor()

    plaintext =  decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext,key,iv


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
    global SESSION_KEY
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


    packet = {args.user: {'ADDRESS' : PEER_LIST[args.user]}}


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


    tagkey = base64.b64decode(server_socket.recv(RECV_BUFFER))

    kt_packet = server_socket.recv(RECV_BUFFER)

    pickle_tgt_key = pickle.loads(kt_packet.decode('base64', 'strict'))


    decryptor = Cipher(
                    algorithms.AES(MASTER_KEY),
                    modes.GCM(MASTER_IV, tagkey),
                    backend=default_backend()
                    ).decryptor()

    tgt = pickle_tgt_key['TGT']



    decryptor = Cipher(
                    algorithms.AES(MASTER_KEY),
                    modes.GCM(MASTER_IV, tagkey),
                    backend=default_backend()
                    ).decryptor()

    key_cipher = pickle_tgt_key['session_key']

    recv_key_plaintext = decryptor.update(key_cipher) + decryptor.finalize()

    SESSION_KEY = recv_key_plaintext

    print 'TGT and session key received'
    print 'Connected to remote server. You can start sending messages'




def list_command():
    print("received list command")
    print PEER_LIST

def send_command(msg):
    sending = msg.split()
    for name in PEER_SOCKETS:
        if sending[1] == name:
            print "sending to existing peer"
            PEER_SOCKETS[name].send(json.dumps({'packet':{"origin": [args.user, PEER_LIST[args.user]], "message": sending[2:]}}))
    else:
        print "need to connect to new peer"
        #step 1 in confirming a new peer
        find_peer_from_server(args, sending[1])
        format_peer_communication(sending)

def format_peer_communication(message):

    packet = {'recipient':message[1], 'packet':{"origin": [args.user, PEER_LIST[args.user]], "message": message[2:]}}
    MESSAGE_QUEUE.append(packet)

def find_peer_from_server(args, peer_name):
    global Server_Nonce
    Server_Nonce = random.randint(0,65535)
    request = {'request': {'name':peer_name,'tgt':args.user,'Na':Server_Nonce}}
    packet = json.dumps(request)
    #encrypt()
    PEER_SOCKETS['server'].send(packet)

def confirm_with_server(connection_message):
    # {Kab || Ns ||TGT(bob)}bmk || {Na}Kab
    #{Ns+1 || TGT(bob) || Nb}Sb
    packet = {}
    for key in connection_message:
        packet[key] = connection_message[key]
    packet['Ns'] = packet['Ns']+1
    Peer_Nonce = random.randint(0,65535)
    packet['Nb'] = Peer_Nonce

    del packet['peer']
    del packet['Kab']
    del packet['g^a mod p']
    ready = {'peer_confirmation': packet}
    PEER_SOCKETS['server'].send(json.dumps(ready))


def accept_peer_connection(pack):
    for x in MESSAGE_QUEUE:
        if pack['peer'] == x['recipient']:
            x['Nb+1'] = pack['Nb']+1
            sock.send(json.dumps(x))
            break


def connect_to_peer(args, connection_packet):
    global Peer_Nonce
    # {Kab || Ns ||TGT(bob)}bmk || {Na}Kab
    pack = connection_packet['connection']
    print pack
    name = pack['peer'][0]
    addr =pack['peer'][1]['ADDRESS']
    print 'connecting to peer'

    PEER_LIST[name] = addr
    # print name
    # print addr
    # print addr[0]
    # print addr[1]

    new_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_peer_socket.settimeout(2)

    # connect to peer server
    try :
        new_peer_socket.connect((addr[0], addr[1]))
    except :
        print 'Unable to connect'
        #sys.exit()

    Peer_Nonce = random.randint(0,65535)
    pack['peer_packet']['peer'] = args.user
    pack['peer_packet']['Na'] = Peer_Nonce
    pack['peer_packet']['g^a mod p'] = random.randint(EX,P)
    new_peer_socket.send(json.dumps(pack['peer_packet']))
    SOCKET_LIST.append(new_peer_socket)
    PEER_SOCKETS[name] = new_peer_socket





def chat_client(args):
    #for testing REMEMBER TO REMOVE
    PORT = args.send_port

    #PEER_LIST = {args.user: ('127.0.0.1', PORT)}
    #I don't know why I needed to declare this global, it suddenly stopped working until I did this
    global PEER_LIST
    global Server_Nonce
    global Peer_Nonce
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
    #unless you know what you're doing, don't f*** with this
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
                #verify new connection
                sockfd, addr = receiving_socket.accept()
                new_peer = json.loads(sockfd.recv(RECV_BUFFER))
                print "connected to new peer"
                print new_peer
                #This needs to move into its own function to be easier to find
                confirm_with_server(new_peer)
                sockfd.send(json.dumps({'peer': args.user, 'Na+1': new_peer['Na']+1, 'g^b mod p': random.randint(EX,P), 'Nb': random.randint(0,65535)}))
                #this is accepting connections regardless at the moment

                SOCKET_LIST.append(sockfd)
                PEER_SOCKETS[new_peer['peer']] = sockfd
                PEER_LIST[new_peer['peer']] = addr


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
                        for key in pack:
                            if key == 'placeholderbecauseImtoolazytorewriteanything':
                                print 'im surprised'
                            elif key == 'connection':
                                print 'red pill'
                                # step 2 in peer connection
                                #{Kab || {Kab || Ns || TGT(bob)}bmk || Na+1 }Sa
                                #initiator check first nonce
                                if pack[key]['Na+1'] == Server_Nonce+1:
                                    connect_to_peer(args, pack)
                                else:
                                    print "bad nonce"
                            elif key == 'peer':
                                #step 4, peer confirmed with server that we are legit, sending messages
                                print "final confirmation"
                                if pack['Na+1'] == Peer_Nonce+1:
                                    accept_peer_connection(pack)
                                else:
                                    print "bad nonce 2"
                                    print pack['Na+1']
                                    print Peer_Nonce

                        else:
                            print 'runoff'
                            #print pack
                        #this is probably temporary
                        #print PEER_LIST
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
                list_command()
                sys.stdout.write('[ME] >'); sys.stdout.flush()
            elif str(msg[:4]) == "send":
                print("got send command")
                send_command(msg)
                sys.stdout.write('[ME] >'); sys.stdout.flush()
            elif str(msg[:6]) == "logout":
                print 'done'
            else:
                print "did we hit?"
                #print("Unrecognized command")
                sys.stdout.write('[ME] >'); sys.stdout.flush()







if __name__ == "__main__":
    #user1$ python ChatClient.py -u Alice -sip server-ip -sp 9090

    args = arguments(sys.argv[1:])
    sys.exit(chat_client(args))
