import sys
import socket
import struct
import textwrap
from scapy.all import *
from collections import Counter
from flask import Flask

# app = Flask(__name__)

flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

ethernet_type = {
    2048: 'IPv4',
}


class Segment:
    def __init__(self, segment, proto_type):
        self.type = proto_type
        self.sport = ''
        self.dport = ''
        self.flags = ''
        if proto_type == 'TCP':
            self.flags = [flags[x] for x in segment.sprintf('%TCP.flags%')]
        if (proto_type == 'TCP') | (proto_type == 'UDP'):
            self.sport = segment.sport
            self.dport = segment.dport

    def __str__(self):
        return "["+str(self.type)+"]$" + " Source Port: {}$ Dst Port: {}$ Flags: {}///".format(str(self.sport), str(self.dport), str(self.flags) + "\n\n")


class Packet:
    """Represents an IP packet"""
    def __init__(self, ip_packet):
        self.version = ip_packet.version
        self.source = ip_packet.src
        self.destination = ip_packet.dst
        self.segment_type = ''
        if ip_packet.haslayer('TCP'):
            self.segment_type = 'TCP'
        elif ip_packet.haslayer('UDP'):
            self.segment_type = 'UDP'

        self.segment = Segment(ip_packet[1], self.segment_type)

    def __str__(self):
        return 'Version: IPv{}$ Source: {}$ Destination: {}$ //\n\t\tSegment: {}'.format(self.version, self.source, self.destination,  self.segment)


class Frame:
    def __init__(self, frame):
        eth_frame = frame[0]
        self.mac_src = eth_frame.src
        self.mac_dst = eth_frame.dst
        self.type = eth_frame.type
        self.ip_packet = Packet(frame[1])

    def __str__(self):
        return "Ethernet Frame: " + '  Source MAC: {}$ Dst MAC: {}$ Type: {}//\n\tPacket: {}'.format(self.mac_src, self.mac_dst, self.type, self.ip_packet)


class PacketSniffer:
    TAB_1 = '\t - '
    TAB_2 = '\t\t - '
    TAB_3 = '\t\t\t - '
    TAB_4 = '\t\t\t\t - '

    DATA_TAB_1 = '\t '
    DATA_TAB_2 = '\t\t '
    DATA_TAB_3 = '\t\t\t '
    DATA_TAB_4 = '\t\t\t\t '

    def custom_action(self, packet):
        packet_counts = Counter()
        # Create tuple of Src/Dst in sorted order
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])
        frame = Frame(packet)
        print(frame)
        sys.stdout.flush()
        # if packet.haslayer('TLS'): return packet[3].show()
        # else: return ""
        # if packet.haslayer('TCP'):
        # return f"Packet #{sum(packet_counts.values())}: {frame}"


    def ethernet_frame(self, data):
        """Unpacks an ethernet frame"""
        dst_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dst_mac), self.get_mac_addr(src_mac), socket.htons(protocol), data[14:]

    def get_mac_addr(self, bytes_addr):
        """Formats MAC address"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        """Unpacks IPv4 packet"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, protocol, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        """Formats IPv4 address"""
        return '.'.join(map(str, addr))

    def icmp_data(self, data):
        """Unpacks ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def tcp_segment(self, data):
        """Unpacks TCP segment"""
        (src_port, dst_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1

        return src_port, dst_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def udp_segment(self, data):
        """Unpack UDP segment"""
        src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dst_port, size, data[8:]

    def format_multi_line(self, prefix, string, size=80):
        """Formats multi line data"""
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


# @app.route("/")
def start():
    my_sniffer = PacketSniffer()
    # print(socket.gethostbyname_ex(socket.gethostname())[2][2])
    load_layer("tls")
    sniff(filter="ip", prn=my_sniffer.custom_action)

    #print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" f key, count in packet_counts.items()))

    host = socket.gethostbyname_ex(socket.gethostname())[2][2]
    # print('IP: {}'.format(host) + str(type(host)))

    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    connection.bind((host, 0))

    connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # while True:
    #     raw_data, addr = connection.recvfrom(65535)
    #     dst_mac, src_mac,eth_protocol, data = ethernet_frame(raw_data)
    #
    #     print('\nEthernet Frame:')
    #     print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dst_mac, src_mac, eth_protocol))
    #
    #     if eth_protocol == 8:
    #         (version, header_length, ttl, protocol, src, target, data) = ipv4_packet(data)
    #         print(TAB_1 + 'IPv4 Packet:')
    #         print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
    #         print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}').format(protocol, src, target)


if __name__ == "__main__":
    sniffer = PacketSniffer()
    # app.run(host='127.0.0.1', port=5000)
    start()


