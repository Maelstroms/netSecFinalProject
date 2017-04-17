# server.py
#python server.py -sp 3000

import sys
import socket
import select
import argparse
import json
import random
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import base64
import pickle


def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-sp', dest='port', required=True, type=int, help="port you want to use for server")
    return parser.parse_args(arglist)


SERVER_MASTER_KEY = os.urandom(32)
SERVER_MASTER_IV = os.urandom(32)


args = arguments(sys.argv[1:])
HOST = ''
#quick data structure to cycle through listening sockets
SOCKET_LIST = []
#CLIENT_SOCKETS is a dictionary that allows easy recall of a client's socket
CLIENT_SOCKETS = {}
#Client list tracks online users and addresses to connect peers
CLIENT_LIST = {}

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"awesome")
key = digest.finalize()

alice_session_key = os.urandom(32)
bob_session_key = os.urandom(32)
carole_session_key = os.urandom(32)
eve_session_key = os.urandom(32)

USER_LIST ={'Alice': {'password':'awesome','master_key': key,'IPaddr':'127.0.0.1','session_key': alice_session_key},
            'Bob': {'password':'awesome','master_key': key,'IPaddr':'127.0.0.1','session_key':bob_session_key},
            'Carole': {'password': 'awesome', 'master_key': key, 'IPaddr': '127.0.0.1', 'session_key': carole_session_key},
            'Eve': {'password': 'awesome', 'master_key': key, 'IPaddr': '127.0.0.1', 'session_key': eve_session_key}}

PUZZLE_ANSWERS = {5 : 3, 8 : 4, 10 : 4}
RECV_BUFFER = 8192
PORT = args.port

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




def check_puzzle():
    pass

def connect_user_to_peer(request):
    unpack_request = request['request']
    cipher_pack = unpack_request['packet']
    source_name = unpack_request['from']
    source_iv = unpack_request['iv']
    source_tag = unpack_request['tag']
    source_key = USER_LIST[source_name]['session_key']

    decryptor = Cipher(
         algorithms.AES(source_key),
         modes.GCM(source_iv, source_tag),
         backend=default_backend()
    ).decryptor()

    json_dict =  decryptor.update(cipher_pack) + decryptor.finalize()
    dict_pack = json.loads(json_dict)

    dest_name = dict_pack['name']
    source_tgt = dict_pack['tgt']
    source_na = dict_pack['Na']


    peer = unpack['name']
    Na = source_na + 1
    shared_secret_key= random.randint(0,65535)
    dest_tgt = CLIENT_LIST[dest_name]['TGT']
    #packet to be sent back to client
    #{Kab || {Kab || Ns || TGT(bob)}bmk || Na+1 }Sa
    peer_encryption_dict = {'Kab': shared_secret, 'Ns': random.randint(0,65535),  'tgt': dest_tgt}
    peer_encryption_packet = json.dumps(peer_encryption_dict)
    peer_iv = os.urandom(12)
    peer_master_key = USER_LIST[dest_name]['master_key']

    encryptor = Cipher(
                    algorithms.AES(peer_master_key),
                    modes.GCM(peer_iv),
                    backend=default_backend()
                    ).encryptor()

    secret_peer_packet = encryptor.update(peer_encryption_packet) + encryptor.finalize()
    peer_tag = encryptor.tag

    #encrypt this
    prep = {'secret': shared_secret_key,'peer': [peer, CLIENT_LIST[peer]], 'peer_packet': secret_peer_packet, 'Na+1': Na}
    packet = json.dumps(prep)

    iv_source = os.urandom(12)

    encryptor = Cipher(
                    algorithms.AES(source_key),
                    modes.GCM(iv_source),
                    backend=default_backend()
                    ).encryptor()

    source_packet_encrypted = encryptor.update(packet) + encryptor.finalize()
    source_tag = encryptor.tag

    final_packet = {'connection' : {'cipher' : source_packet_encrypted, 'source_iv' : iv_source, 'source_tag' : source_tag, 'peer_iv' : peer_iv, "peer_tag" : peer_tag}}
    traveler = pickle.dumps(final_packet)
    traveler = traveler.encode('base64', 'strict')
    
    CLIENT_SOCKETS[user].send(traveler)


def confirm_connection(request):
    packet = request['peer_confirmation']
    peer = packet['tgt']
    confirmation = {'Nb+1': packet['Nb']+1}
    CLIENT_SOCKETS[peer].send(json.dumps(confirmation))


# time.time() returns the time as a floating point number expressed in seconds since the epoch, in UTC.
# create_new_tgt : Username --> TGT
# GIVEN : Username
# RETURNS : A newly created TGT which is a list of username, session key and time stamp

def create_new_tgt (username) :
    encryptor = Cipher(
                    algorithms.AES(SERVER_MASTER_KEY),
                    modes.GCM(SERVER_MASTER_IV),
                    backend=default_backend()
                    ).encryptor()

    proto_session= USER_LIST[username]['session_key']
    proto_tgt = [username,repr(proto_session),time.time()]
    string_tgt = json.dumps(proto_tgt)
    cipher_TGT = encryptor.update(repr(string_tgt))+ encryptor.finalize()
    tgt_encryption_tag = encryptor.tag

    CLIENT_LIST[username]['TGT'] = [cipher_TGT, tgt_encryption_tag]

    return cipher_TGT, [tgt_encryption_tag]

#check_expired_tgt : TGT -> TGT
#GIVEN : TGT
#RETURNS : Checks if the current TGT is expired or not, if expired then creates a new TGT else returns the same
def check_expired_tgt (tgt) :
    if (time.time() - tgt[2] > 3600) :
        return create_new_tgt(tgt[0])
    else :
        return tgt

def chat_server():

    global key
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    # add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)

    print "Chat server started on port " + str(PORT)

    while 1:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)

        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket:
                print("got a hit")
                sockfd, addr = server_socket.accept()
                newUser = json.loads(sockfd.recv(RECV_BUFFER))
                print newUser
                for name in newUser:
                    CLIENT_LIST[name] = newUser[name]
                user_name = newUser.keys()[0]

                if(USER_LIST.has_key(user_name)) :
                    print("User is a registered user!!")

                else :
                     break #TO BE FIXED

                #get a random number for puzzle

                puz_num = PUZZLE_ANSWERS.keys()[0]

                print puz_num
                print PUZZLE_ANSWERS[puz_num]

                sockfd.send(pickle.dumps({'puzz':puz_num}).encode('base64', 'strict'))
####################################################################################

                aes_packet =  sockfd.recv(RECV_BUFFER)
                
                aes_packet_pickle = pickle.loads(aes_packet.decode('base64', 'strict'))
                crypt_answer = aes_packet_pickle['solution']
                user_iv = aes_packet_pickle['iv']
                user_tag = aes_packet_pickle['tag']



                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(user_iv, user_tag),
                    backend=default_backend()
                    ).decryptor()

                
                decrypted_puzz_packet = decryptor.update(crypt_answer) + decryptor.finalize()
                decrypted_puzz_packet = json.loads(decrypted_puzz_packet    )
               
                puz_answer = decrypted_puzz_packet['puzzle']

                if(puz_answer != PUZZLE_ANSWERS[puz_num]) :
                    print ("User is malicious")
                    break ##TO BE FIXED

                #add sockfd to the listening loop
                SOCKET_LIST.append(sockfd)
                #receive new user credentials


                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(user_iv),
                    backend=default_backend()
                    ).encryptor()



                tgt,tagsserver = create_new_tgt(user_name)
                usersionkey = USER_LIST[user_name]['session_key']

                #cipherskey = encryptor.update(usersionkey) + encryptor.finalize()
                cipherkt = {'TGT' : repr(tgt), 'session_key' : repr(usersionkey), 'Na+1': decrypted_puzz_packet['Na']+1}
                cipherkt = encryptor.update(json.dumps(cipherkt)) + encryptor.finalize()
                cipherkt_packet_pickle = cipherkt

                tagkey = encryptor.tag
                #tagkeyen = base64.b64encode(tagkey)
                accept_user_packet = {'accepted': {'acceptance':cipherkt_packet_pickle, 'tag':tagkey, 'IV':user_iv}}
                
                traveler = pickle.dumps(accept_user_packet)
                traveler = traveler.encode('base64', 'strict')
                
                sockfd.send(traveler)

                CLIENT_LIST[user_name] = newUser[user_name]
                
                #CLIENT_LIST[user_name]['session_key'] = usersionkey
                CLIENT_SOCKETS[user_name] = sockfd
                #print "adress is " + str(addr.append(newUser))
                print "Client (%s, %s) connected" % addr
                print SOCKET_LIST
                print CLIENT_SOCKETS
                print CLIENT_LIST



            #not a new connection
            else:
                # process data recieved from client,
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        print 'data data'
                        request = pickle.loads(data.decode('base64', 'strict'))
                        
                        #received request to connect to peer
                        for key in request:
                            if key == 'placeholderbecauseImtoolazytorewriteanything':
                                print 'im surprised'
                            elif key == 'request':
                                connect_user_to_peer(request)
                            elif key == 'peer_confirmation':
                                print request
                                confirm_connection(request)


                        #'peer_confirmation'
                        #print 'should be dead'
                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                            break


                        # at this stage, no data means probably the connection has been broken
                # exception
                except Exception as inst:
                    print "we lost our shit"
                    print(type(inst))    # the exception instance
                    print(inst.args)     # arguments stored in .args
                    print(inst)          # __str__ allows args to be printed directly,
                                         # but may be overridden in exception subclasses

                    break

    server_socket.close()



if __name__ == "__main__":
    sys.exit(chat_server())