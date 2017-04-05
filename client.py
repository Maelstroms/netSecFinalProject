# chat_client.py
#python client.py -u Alice -sip 127.0.0.1 -sp 3000

import sys
import socket
import select
import argparse
import json
import random

PEER_LIST = {}
PEER_SOCKETS = {}
SOCKET_LIST =[]
RECV_BUFFER = 4096
HOST = ''
PORT = random.randint(0,65535)

def arguments(arglist):
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('-u', required=True, dest='user', help="User to be logged into server")
    #parser.add_argument('-p', required=True, dest='userPass', help="User password for server authentication")
    parser.add_argument('-sip', required=True, dest='server', help="IP address of the server")
    parser.add_argument('-sp', required=True, dest='port', type=int, help="port to connect to server")
    return parser.parse_args(arglist)



def server_authentication(args):
    user = args.user
    server_address = args.server
    port = args.port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(2)
    print 'hell'

    # connect to remote server
    try :
        server_socket.connect((server_address, port))
    except :
        print 'Unable to connect'
        sys.exit()


    first_packet = json.dumps(PEER_LIST)
    server_socket.send(first_packet)
    SOCKET_LIST.append(server_socket)
    PEER_SOCKETS['server'] = server_socket
    print 'Connected to remote server. You can start sending messages'


def connect_to_peer(name, addr):
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



def chat_client(args):
    #PEER_LIST = {args.user: ('127.0.0.1', PORT)}
    global PEER_LIST
    PEER_LIST[args.user] = ('127.0.0.1', PORT)

    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiving_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receiving_socket.bind((HOST, PORT))
    receiving_socket.listen(10)
    SOCKET_LIST.append(receiving_socket)


    server_authentication(args)



    sys.stdout.write('[ME] >'); sys.stdout.flush()
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
                        sys.stdout.write("\n")
                        # this may need to change
                        pack = json.loads(data)
                        for key in pack:
                            if key == 'peer':
                                PEER_LIST = pack[key]
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
                    print(type(inst))    # the exception instance
                    print(inst.args)     # arguments stored in .args
                    print(inst)          # __str__ allows args to be printed directly,
                                         # but may be overridden in exception subclasses


        msg = sys.stdin.readline()
        if str(msg) == "list\n":
            #received list command
            print("received list command")
            print PEER_LIST
            sys.stdout.write('[ME] >'); sys.stdout.flush()
        elif str(msg[:4]) == "send":
            print("get send")
            sending = msg.split()
            for name in PEER_LIST:
                print sending
                print sending[1]
                packet = json.dumps({"origin": [args.user, PEER_LIST[args.user]], "message": sending[2]})
                print packet
                if sending[1] == name:
                    print("received send command")
                    if name in PEER_SOCKETS:
                        print "sending to existing peer"
                        PEER_SOCKETS[name].send(packet)
                        #PEER_SOCKETS[name].send("\r" + '[FROM' + str(sock.getpeername()) + name + '] ' + " ".join(sending[2:])+"\n")
                    else:
                        print "need to connect to new peer"
                        connect_to_peer(name, PEER_LIST[name])
                        PEER_SOCKETS[name].send(packet)
                    sys.stdout.write('[ME] >'); sys.stdout.flush()
                else:
                    print "error, no such user"
                    sys.stdout.write('[ME] >'); sys.stdout.flush()


        else:
            print "did we hit?"
            #print("Unrecognized command")
            sys.stdout.write('[ME] >'); sys.stdout.flush()







if __name__ == "__main__":
    #user1$ python ChatClient.py -u Alice -sip server-ip -sp 9090

    args = arguments(sys.argv[1:])
    sys.exit(chat_client(args))
