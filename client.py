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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
import base64
import pickle
import pyDH

backend = default_backend()

TGT = {}
#final form of Peer entries:
#'Alice':{'ADDRESS': ['127.0.0.1', 9091], 'TGT':{}, 'encryption_key':key}
PEER_LIST = {}
PEER_SOCKETS = {}
SOCKET_LIST =[]
RECV_BUFFER = 8192
HOST = ''
PORT = random.randint(0,65535)

MESSAGE_QUEUE = []
Server_Nonce = 0
Peer_Nonce = 0

DH_PRIV = 0#pyDH.DiffieHellman()
DH_PUB = 0#DH_PRIV.gen_public_key()
DH_SHARED = 0 #DH_PRIV.gen_shared_key(DH_PUB)


MASTER_IV = os.urandom(12)
MASTER_PASSWORD = 'awesome'

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"awesome")
MASTER_HASH = digest.finalize()
MASTER_KEY = MASTER_HASH

#for testing P2P encryption
USER_LIST ={'Alice': {'password':'awesome','server_master_key':42,'IPaddr':'127.0.0.1','session_key':54784},
'Bob': {'password':'awesome','server_master_key':69,'IPaddr':'127.0.0.1','session_key':54784}}

def make_aes_key(key):
    return key[0:32]

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

    return ciphertext,tag


def decryptor(key,iv,tag,ciphertext):

    decryptor = Cipher(
         algorithms.AES(key),
         modes.GCM(iv, tag),
         backend=default_backend()
    ).decryptor()

    plaintext =  decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


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

    PEER_LIST['server'] = {'ADDRESS' : (server_address, port)}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(2)

    # connect to remote server
    print 'connecting'
    try :
        server_socket.connect((server_address, port))
    except :
        print 'Unable to connect'
        sys.exit()


    packet = {args.user: PEER_LIST[args.user]}


    first_packet = json.dumps(packet)
    server_socket.send(first_packet)
    SOCKET_LIST.append(server_socket)
    PEER_SOCKETS['server'] = server_socket


def solve_puzzle(args, pack):
    server_socket = PEER_SOCKETS['server']
    puz_num = pack['puzz']

    ans_puz = len (get_primes(puz_num))

    encryptor = Cipher(
        algorithms.AES(MASTER_KEY),
        modes.GCM(MASTER_IV),
        backend=default_backend()
    ).encryptor()

    Na = random.randint(0,65535)
    puzz_ans_packet = {'puzzle': ans_puz, 'Na': Na}
    packet_prep = json.dumps(puzz_ans_packet)

    cipherpuzzle = encryptor.update(packet_prep) + encryptor.finalize()
    tag = encryptor.tag


    aes_packet = {'solution' : cipherpuzzle, 'iv' : MASTER_IV, 'tag' : tag}
    aes_packet_pickle = pickle.dumps(aes_packet).encode('base64', 'strict')


    server_socket.send(aes_packet_pickle)



def receive_session_key(args, data):
    #print data
    print 'SESSION STUFF'
    server_socket = PEER_SOCKETS['server']
    tagkey = data['tag']
    kt_packet = data['acceptance']
    iv = data['IV']


    decryptor = Cipher(
                    algorithms.AES(MASTER_KEY),
                    modes.GCM(iv, tagkey),
                    backend=default_backend()
                    ).decryptor()


    decrypted_packet = json.loads(decryptor.update(kt_packet) + decryptor.finalize())
    #add nonce check
    PEER_LIST['server']['session_key'] = decrypted_packet['session_key']
    PEER_LIST[args.user]['TGT'] = decrypted_packet['TGT']


    print 'TGT and session key received'
    print PEER_LIST
    print 'Connected to remote server. You can start sending messages'


def list_command(args):
    print("received list command")
    #PEER_LIST['server']
    pickled_packet = pickle.dumps({'list_please':args.user})
    PEER_SOCKETS['server'].send(base64.b64encode(pickled_packet))
    print PEER_LIST


def send_command(msg):
    print 'got a command to send a message'
    sending = msg.split()
    for name in PEER_SOCKETS:
        if sending[1] == name:
            print "sending to existing peer"
            key = make_aes_key(PEER_LIST[name]['encryption_key'])
            iv = os.urandom(32)
            encryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv),
                    backend=default_backend()
                    ).encryptor()
            encryption_prep = json.dumps({'packet':{"origin": [args.user, PEER_LIST[args.user]], "message": sending[2:]}})
            cipherkt = encryptor.update(json.dumps(encryption_prep)) + encryptor.finalize()
            tagkey = encryptor.tag

            pickled_packet = pickle.dumps({'p2p': cipherkt, 'IV': iv, 'TAG':tagkey, 'from': args.user})
            sock.send(base64.b64encode(pickled_packet))
    else:
        print "need to connect to new peer"
        #step 1 in confirming a new peer
        find_peer_from_server(args, sending[1])
        format_peer_communication(sending)


def format_peer_communication(message):
    print 'cache message for later'
    packet = {'recipient':message[1], 'packet':{"origin": args.user, "message": message[2:]}}
    MESSAGE_QUEUE.append(packet)


def find_peer_from_server(args, peer_name):
    print "get address from server"
    global Server_Nonce
    Server_Nonce = random.randint(0,65535)
    encrypted_section = {'name':peer_name,'TGT':args.user,'Na':Server_Nonce}
    request = {'request': encrypted_section}
    packet = pickle.dumps(request).encode('base64', 'strict')
    PEER_SOCKETS['server'].send(packet)



def connect_to_peer(args, connection_packet):
    print "connecting to peer"
    global Peer_Nonce
    global DH_PRIV
    global DH_PUB
    # {Kab || Ns ||TGT(bob)}bmk || {Na}Kab
    pack = connection_packet['connection']
    name = pack['peer'][0]
    addr =pack['peer'][1]['ADDRESS']
    PEER_LIST[name] = {'ADDRESS': addr}
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

    print "passing on packet"
    Peer_Nonce = random.randint(0,65535)
    forwarded_message = {'return_to_server':pack['peer_packet']}
    forwarded_message['peer'] = args.user
    forwarded_message['Na'] = Peer_Nonce
    #der format
    DH_PRIV = pyDH.DiffieHellman()
    DH_PUB = DH_PRIV.gen_public_key()
    forwarded_message['g^a mod p'] = DH_PUB
    encryption_prep = pickle.dumps(forwarded_message).encode('base64', 'strict')
    pickle_barrel = pickle.dumps({'peer':encryption_prep}).encode('base64', 'strict')
    new_peer_socket.send(pickle_barrel)

    SOCKET_LIST.append(new_peer_socket)
    PEER_SOCKETS[name] = new_peer_socket


def confirm_with_server(connection_message):
    print "ask server for legitimacy"
    # {Kab || Ns ||TGT(bob)}bmk || {Na}Kab
    #{Ns+1 || TGT(bob) || Nb}Sb
    message_from_A = pickle.loads(connection_message['peer'].decode('base64', 'strict'))
    message_to_server = json.loads(message_from_A['return_to_server'])
    message_to_server['Ns'] = message_to_server['Ns']+1
    Peer_Nonce = random.randint(0,65535)
    message_to_server['Nb'] = Peer_Nonce


    encryption_prep = json.dumps(message_to_server)
    ready = {'peer_confirmation': encryption_prep}
    pickled_packet = pickle.dumps(ready).encode('base64', 'strict')
    PEER_SOCKETS['server'].send(pickled_packet)


def server_legitimizes(new_peer, sockfd, addr):
    print 'responding to hopeful peer'
    global DH_PRIV
    global DH_PUB
    global DH_SHARED
    new_peer = pickle.loads(new_peer['peer'].decode('base64', 'strict'))
    PEER_SOCKETS[new_peer['peer']] = sockfd
    PEER_LIST[new_peer['peer']] ={'ADDRESS':  addr }
    DH_PRIV = pyDH.DiffieHellman()
    DH_PUB = DH_PRIV.gen_public_key()
    DH_SHARED = DH_PRIV.gen_shared_key(new_peer['g^a mod p'])
    PEER_LIST[new_peer['peer']]['encryption_key'] = DH_SHARED
    encryption_prep = pickle.dumps({'peer': args.user, 'Na+1': new_peer['Na']+1, 'g^b mod p': DH_PUB, 'Nb': random.randint(0,65535)}).encode('base64', 'strict')
    pickle_barrel = pickle.dumps({'buddy':encryption_prep}).encode('base64', 'strict')
    sockfd.send(pickle_barrel)



def accept_peer_connection(args, pack, sock):
    print "send chached message"
    global DH_PRIV
    global DH_PUB
    global DH_SHARED
    pack = pickle.loads(pack['buddy'].decode('base64', 'strict'))
    name = pack['peer']
    DH_SHARED = DH_PRIV.gen_shared_key(pack['g^b mod p'])
    PEER_LIST[name]['encryption_key'] = DH_SHARED
    for x in MESSAGE_QUEUE:
        if name == x['recipient']:
            x['Nb+1'] = pack['Nb']+1
            encryption_prep = json.dumps(MESSAGE_QUEUE.pop(MESSAGE_QUEUE.index(x)))

            #dh makes 2048 bit dh key, aes only takes 512
            key = make_aes_key(PEER_LIST[name]['encryption_key'])

            iv = os.urandom(32)
            encryptor = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv),
                        backend=default_backend()
                        ).encryptor()
            cipherkt = encryptor.update(json.dumps(encryption_prep)) + encryptor.finalize()
            tagkey = encryptor.tag

            pickled_packet = pickle.dumps({'p2p': cipherkt, 'IV': iv, 'TAG':tagkey, 'from': args.user})
            sock.send(base64.b64encode(pickled_packet))

            break

def decode_p2p(pack, sock):
    print 'p2p decoding'
    print pack
    name = pack['from']
    key = make_aes_key(PEER_LIST[name]['encryption_key'])

    tag = pack['TAG']

    iv = pack['IV']
    decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                    ).decryptor()
    plaintext =  decryptor.update(pack['p2p']) + decryptor.finalize()
    print plaintext












###################################################################################
#  MAIN
def chat_client(args):
    #for testing REMEMBER TO REMOVE
    PORT = args.send_port

    #PEER_LIST = {args.user: ('127.0.0.1', PORT)}
    #I don't know why I needed to declare this global, it suddenly stopped working until I did this
    global PEER_LIST
    global Server_Nonce
    global Peer_Nonce
    #for self identification
    PEER_LIST[args.user] = {'ADDRESS': ['127.0.0.1', PORT]}

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
    counter = 0
    while 1:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
        #print SOCKET_LIST


        for sock in ready_to_read:
            print 'cycle number'
            counter+=1
            print counter
            if sock == receiving_socket:
                print "got the listener"
                #verify new connection
                sockfd, addr = receiving_socket.accept()
                new_peer = pickle.loads(sockfd.recv(RECV_BUFFER).decode('base64', 'strict'))
                print "connected to new peer"
                print new_peer
                #This needs to move into its own function to be easier to find
                SOCKET_LIST.append(sockfd)

                confirm_with_server(new_peer)
                server_legitimizes(new_peer, sockfd, addr)

                #this is accepting connections regardless at the moment




        # process data recieved from client,
            else:
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        #make titles for data packets for sorting and use
                        sys.stdout.write("\n"); sys.stdout.flush()
                        pack = pickle.loads(base64.b64decode(data))
                        #pack = json.loads(pickled_data)
                        print pack
                        for key in pack:
                            if False: #key == 'placeholderbecauseImtoolazytorewriteanything':
                                print 'im surprised'
                            elif key == 'puzz':
                                print 'got a puzzle'
                                solve_puzzle(args, pack)
                            elif key == 'accepted':
                                print 'server accepted us!'
                                receive_session_key(args, pack['accepted'])
                            elif key == 'connection':
                                print 'red pill'
                                # step 2 in peer connection
                                #{Kab || {Kab || Ns || TGT(bob)}bmk || Na+1 }Sa
                                #initiator check first nonce
                                #if pack[key]['Na+1'] == Server_Nonce+1:
                                connect_to_peer(args, pack)
                            elif key == 'buddy':
                                #step 4, peer confirmed with server that we are legit, sending messages
                                print "final confirmation"
                                # if pack['Na+1'] == Peer_Nonce+1:
                                accept_peer_connection(args, pack, sock)
                                # else:
                                #     print "bad nonce 2"
                                #     print pack['Na+1']
                                #     print Peer_Nonce
                            elif key == 'p2p':
                                decode_p2p(pack, sock)
                            elif key == 'peers_listed':
                                print pack[key]
                                # PEER_LIST =

                        else:
                            print 'runoff'
                            #print pack
                        #this is probably temporary
                        #print PEER_LIST
                        #print pack
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
                list_command(args)
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
