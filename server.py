# chat_server.py

import sys
import socket
import select
import argparse

def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-sp', dest='port', required=True, type=int, help="port you want to use for server")
    return parser.parse_args(arglist)

args = arguments(sys.argv[1:])
HOST = ''
SOCKET_LIST = []
CLIENT_LIST = []
RECV_BUFFER = 4096
PORT = args.port

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
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                newUser = sockfd.recv(RECV_BUFFER)
                CLIENT_LIST.append(newUser)
                #print "adress is " + str(addr.append(newUser))
                print "Client (%s, %s) connected" % addr
                print SOCKET_LIST
                print CLIENT_LIST

                broadcast(server_socket, sockfd, "[%s:%s] entered our chatting room\n" % addr)

                    # newUser = sock.recv(RECV_BUFFER)
                    # CLIENT_LIST.append(newUser)


            # a message from a client, not a new connection
            else:
                # process data recieved from client,
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        if str(data) == "list\n":
                            #received list command
                            print("received list command")
                            sock.send("Signed In Users: " +str(CLIENT_LIST)+"\n")
                        elif data[:4] == "send":
                            print("get send")
                            sending = data.split()
                            for name in CLIENT_LIST:
                                if sending[1] == name:
                                    print("received send command")
                                    SOCKET_LIST[CLIENT_LIST.index(name)+1].send("\r" + '[FROM' + str(sock.getpeername()) + name + '] ' + " ".join(sending[2:])+"\n")
                                    #break
                            # else:
                            #     continue
                        else:
                            # there is something in the socket
                            print(data)
                            print(CLIENT_LIST[SOCKET_LIST.index(sock) - 1])
                            broadcast(server_socket, sock, "\r" + '[FROM' + str(sock.getpeername()) + CLIENT_LIST[SOCKET_LIST.index(sock) - 1] + '] ' + data)
                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        # at this stage, no data means probably the connection has been broken
                        broadcast(server_socket, sock, "Client (%s, %s)"% addr + CLIENT_LIST[SOCKET_LIST.index(sock) - 1] + " is offline\n" )

                # exception
                except Exception as inst:
                    print(type(inst))    # the exception instance
                    print(inst.args)     # arguments stored in .args
                    print(inst)          # __str__ allows args to be printed directly,
                                         # but may be overridden in exception subclasses
                    broadcast(server_socket, sock, "Client (%s, %s)"% addr + CLIENT_LIST[SOCKET_LIST.index(sock) - 1] + " is offline\n")#this on defaults
                    continue

    server_socket.close()

# broadcast chat messages to all connected clients
def broadcast (server_socket, sock, message):
    for socket in SOCKET_LIST:
        # send the message only to peer
        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :
                # broken socket connection
                socket.close()
                # broken socket, remove it
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

if __name__ == "__main__":
    sys.exit(chat_server())
