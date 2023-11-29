from packet_struct import *
import struct
import sys
from collections import defaultdict


def parse_cap_file(filename):
    connections = defaultdict(Connection)
    with open(filename, 'rb') as file:

        global_header = file.read(24)
        magic_number, _, _, _, _, _, _ = struct.unpack(
            "IHHIIII", global_header)

        ms = True
        orig_time = 0
        packet_number = 1

        packet_header = file.read(16)
        # Get Timestamp of first packet

        if magic_number == 0xa1b2c3d4:
            print("Big Endian, microseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('<I', packet_header[4:8])[0]*0.000001)
        elif magic_number == 0xd4c3b2a1:
            print("Little Endian, microseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('>I', packet_header[4:8])[0]*0.000001)
        elif magic_number == 0xa1b23c4d:
            print("Big Endian, nanoseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('<I', packet_header[4:8])[0]*0.000000001)
            ms = False
        elif magic_number == 0x4d3cb2a1:
            print("Little Endian, nanoseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('>I', packet_header[4:8])[0]*0.000000001)
            ms = False
        else:
            print("Invalid PCAP file format.")
            return

        while True:
            if not packet_header:
                break
            _, _, incl_len, _ = struct.unpack('IIII', packet_header)
            if incl_len == 0:
                break
            buffer = file.read(incl_len)
            curPacket = parse_packet(buffer)
            if curPacket == None:
                packet_number += 1
                file.read(16)
                continue
            curPacket.packet_No_set(packet_number)
            curPacket.timestamp_set(
                packet_header[0:4], packet_header[4:8], orig_time, ms)
            process_packet(curPacket, connections)

            # Move to next packet
            packet_number += 1
            packet_header = file.read(16)

    return connections


def parse_packet(buffer):
    curPacket = packet()
    i = 0
    # Ethernet Header [0:14]
    i += 14
    # First 20 bytes of IPHEADER [14:34]
    ip_header_buffer = buffer[i: i + 20]
    i += 20
    get_IP_info(curPacket, ip_header_buffer)

    if curPacket.IP_header.protocol != 17 and curPacket.IP_header.protocol != 1:
        print(curPacket.IP_header.src_ip)
        print(curPacket.IP_header.dst_ip)
        print("---------------")
        return None
    print(curPacket.IP_header.dst_ip)

    # If IP Header is longer than 20 bytes, read options
    if curPacket.IP_header.ip_header_len > 20:
        i += curPacket.IP_header.ip_header_len - 20

    # If UDP
    if curPacket.IP_header.protocol == 17:
        # First 8 bytes of TCPHeader
        udp_buffer = buffer[i:i+8]
        i += 8
        curUDP = UDP_Header()
        curUDP.get_UDP(udp_buffer)
        curPacket.UDP_header = curUDP
    else:
        icmp_buffer = buffer[i:i+8]
        i += 8
        curICMP = ICMP_Header()
        curICMP.get_ICMP(icmp_buffer)
        curPacket.ICMP_header = curICMP

    return curPacket


def get_IP_info(curPacket, ip_header_buffer):
    curPacket.IP_header.get_header_len(ip_header_buffer[0:1])
    curPacket.IP_header.get_total_len(ip_header_buffer[2:4])
    curPacket.IP_header.get_fragment_offset(ip_header_buffer[6:8])
    curPacket.IP_header.get_more_fragments(ip_header_buffer[6:8])
    curPacket.IP_header.get_ttl(ip_header_buffer[8:9])
    curPacket.IP_header.get_protocol(ip_header_buffer[9:10])
    curPacket.IP_header.get_IP(
        ip_header_buffer[12:16], ip_header_buffer[16:20])


def process_packet(curPacket, connections):
    source_ip = curPacket.IP_header.src_ip
    destination_ip = curPacket.IP_header.dst_ip
    protocol = curPacket.IP_header.protocol
    mf = curPacket.IP_header.mf
    fragment_offset = curPacket.IP_header.fragment_offset
    source_port = curPacket.UDP_header.src_port
    destination_port = curPacket.UDP_header.dst_port
    timestamp = curPacket.timestamp
    type = curPacket.ICMP_header.type

    connection_id = f"{source_ip}:{source_port}-{destination_ip}:{destination_port}"
    src_to_dst = f"{destination_ip}:{destination_port}-{source_ip}:{source_port}"
    if connection_id not in connections and src_to_dst not in connections:
        print(connection_id)
        connections[connection_id] = Connection()
        connections[connection_id].source_ip = source_ip
        connections[connection_id].destination_ip = destination_ip
        connections[connection_id].source_port = source_port
        connections[connection_id].destination_port = destination_port

    connection = connections[connection_id]
    connection.fragment_offset = fragment_offset

    print(type)
    if (type == 11) and source_ip not in connection.intermediate_dsts:
        connection.intermediate_dsts.append(source_ip)

    if (mf or fragment_offset > 0):
        connection.num_frags += 1
    connection.start_time = timestamp
    if protocol not in connection.protocols and (protocol == 1 or protocol == 17):
        connection.protocols.append(protocol)


def print_connection_info(connections):
    protocols = {1: "ICMP",
                 17: "UDP"}

    for connection in connections.values():
        print(f"Source IP: {connection.source_ip}")
        print(f"Destination IP: {connection.destination_ip}")

        print("Intermediate Destination Nodes:")
        for i, intermediate_dest in enumerate(connection.intermediate_dsts, start=1):
            print(f"{i}. {intermediate_dest}")

        print("\nProtocol Values:")
        for protocol in connection.protocols:
            print(f"{protocol}: {protocols[protocol]}")

        print(f"\nNumber of Fragments: {connection.num_frags}")
        print(f"Offset of Last Fragment: {connection.fragment_offset}")
        print("\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CapReader.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    connections = parse_cap_file(filename)
    print_connection_info(connections)
