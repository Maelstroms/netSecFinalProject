# server.py
#python server.py -sp 3000

import sys
import socket
import select
import argparse
import json
import random

def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-sp', dest='port', required=True, type=int, help="port you want to use for server")
    return parser.parse_args(arglist)

SERVER_MASTER_KEY = 0
args = arguments(sys.argv[1:])
HOST = ''
#quick data structure to cycle through listening sockets
SOCKET_LIST = []
#CLIENT_SOCKETS is a dictionary that allows easy recall of a client's socket
CLIENT_SOCKETS = {}
#Client list tracks online users and addresses to connect peers
#CLIENT_LIST = {}
CLIENT_LIST = {'Alice':('127.0.0.1', 9091),'Bob':('127.0.0.1', 9092)}
#user list with passwords

USER_LIST ={'Alice': {'password':'awesome','master_key':42,'IPaddr':'127.0.0.1','session_key':54784},
'Bob': {'password':'awesome','master_key':42,'IPaddr':'127.0.0.1','session_key':54784}}
RECV_BUFFER = 4096
PORT = args.port

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


def connect_user_to_peer(request):
    unpack = request['request']
    user = unpack['tgt']
    peer = unpack['name']
    Na = unpack['Na'] + 1
    shared_secret= random.randint(0,65535)
    #packet to be sent back to client
    #{Kab || {Kab || Ns || TGT(bob)}bmk || Na+1 }Sa
    peer_encryption = {'Kab': shared_secret, 'Ns': random.randint(0,65535),  'tgt': peer}
    prep = {'secret': shared_secret,'peer': [peer, CLIENT_LIST[peer]], 'peer_packet': peer_encryption, 'Na+1': Na}
    packet = json.dumps({'connection': prep})
    print packet
    CLIENT_SOCKETS[user].send(packet)

def confirm_connection(request):
    packet = request['peer_confirmation']
    peer = packet['tgt']
    confirmation = {'Nb+1': packet['Nb']+1}
    CLIENT_SOCKETS[peer].send(json.dumps(confirmation))

def chat_server():

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
                #add sockfd to the listening loop
                SOCKET_LIST.append(sockfd)
                #receive new user credentials
                newUser = json.loads(sockfd.recv(RECV_BUFFER))
                print newUser
                user_name = newUser.keys()[0]
                CLIENT_LIST[user_name] = newUser[user_name]
                CLIENT_SOCKETS[user_name] = sockfd
                #print "adress is " + str(addr.append(newUser))
                print "Client (%s, %s) connected" % addr
                print SOCKET_LIST
                print CLIENT_SOCKETS
                print CLIENT_LIST
                brd = {"peer": CLIENT_LIST}
                brd = json.dumps(brd)
                print brd


                    # newUser = sock.recv(RECV_BUFFER)
                    # CLIENT_LIST.append(newUser)


            #not a new connection
            else:
                # process data recieved from client,
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        print 'data data'
                        request = json.loads(data)
                        print request
                        #received request to connect to peer
                        for key in request:
                            if key == 'request':
                                connect_user_to_peer(request)
                            elif key == 'peer_confirmation':
                                print request
                                confirm_connection(request)


                        #'peer_confirmation'
                        print 'should be dead'
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
