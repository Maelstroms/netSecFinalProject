# server.py
#python server.py -sp 9090

import sys
import socket
import select
import argparse
import json

def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-sp', dest='port', required=True, type=int, help="port you want to use for server")
    return parser.parse_args(arglist)

args = arguments(sys.argv[1:])
HOST = ''
SOCKET_LIST = []
#Client list tracks online users
CLIENT_LIST = {}
#user list with passwords

USER_LIST = {'Alice':1,
            'Bob':2,
            'Carole':3,
            'Eve':4}
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

def connect_user_to_peer():
    pass

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
                SOCKET_LIST.append(sockfd)
                #receive new user credentials
                newUser = json.loads(sockfd.recv(RECV_BUFFER))
                user_name = newUser.keys()[0]
                CLIENT_LIST[user_name] = newUser[user_name]
                #print "adress is " + str(addr.append(newUser))
                print "Client (%s, %s) connected" % addr
                print SOCKET_LIST
                print CLIENT_LIST
                brd = {"peer": CLIENT_LIST}
                brd = json.dumps(brd)
                print brd
                broadcast(server_socket, sockfd, brd)

                    # newUser = sock.recv(RECV_BUFFER)
                    # CLIENT_LIST.append(newUser)


            #not a new connection
            else:
                # process data recieved from client,
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        pass
                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                            break


                        # at this stage, no data means probably the connection has been broken
                        #broadcast(server_socket, sock, "Client (%s, %s)"% addr + CLIENT_LIST[SOCKET_LIST.index(sock) - 1] + " is offline\n" )

                # exception
                except Exception as inst:
                    print(type(inst))    # the exception instance
                    print(inst.args)     # arguments stored in .args
                    print(inst)          # __str__ allows args to be printed directly,
                                         # but may be overridden in exception subclasses
                    #broadcast(server_socket, sock, "Client (%s, %s)"% addr + CLIENT_LIST[SOCKET_LIST.index(sock) - 1] + " is offline\n")#this on defaults
                    break

    server_socket.close()

# broadcast chat messages to all connected clients, here for development purposes
def broadcast (server_socket, sock, message):
    for socket in SOCKET_LIST:
        # send the message only to peer
        if socket != server_socket:
            print("working?")
            try :
                print("yay")
                socket.send(message)
            except :
                print("nay")
                # broken socket connection
                socket.close()
                # broken socket, remove it
                if socket in SOCKET_LIST:
                    pass
                    SOCKET_LIST.remove(socket)

if __name__ == "__main__":
    sys.exit(chat_server())
