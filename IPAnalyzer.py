from packet_struct import *
import struct
import sys
from collections import defaultdict

trace = Traceroute()


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
                0] + (struct.unpack('<I', packet_header[4:8])[0]*1e-6)

        elif magic_number == 0xd4c3b2a1:
            print("Little Endian, microseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('>I', packet_header[4:8])[0]*1e-6)

        elif magic_number == 0xa1b23c4d:
            print("Big Endian, nanoseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('<I', packet_header[4:8])[0]*1e-9)
            ms = False

        elif magic_number == 0x4d3cb2a1:
            print("Little Endian, nanoseconds")
            orig_time = struct.unpack('I', packet_header[0:4])[
                0] + (struct.unpack('>I', packet_header[4:8])[0]*1e-9)
            ms = False
        else:
            print("Invalid PCAP file format.")
            return

        while True:
            if not packet_header:
                break
            _, _, _, orig_len = struct.unpack('IIII', packet_header)
            buffer = file.read(orig_len)
            if len(buffer) == 0:
                break
            curPacket = parse_packet(buffer)
            if curPacket == None:
                packet_number += 1
                packet_header = file.read(16)
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
    global trace
    curPacket = packet()
    i = 0
    # Ethernet Header [0:14]
    i += 14
    # First 20 bytes of IPHEADER [14:34]
    ip_header_buffer = buffer[i: i + 20]
    i += 20
    get_IP_info(curPacket, ip_header_buffer)
    # If IP Header is longer than 20 bytes, read options
    if curPacket.IP_header.ip_header_len > 20:
        i += curPacket.IP_header.ip_header_len - 20

    if curPacket.IP_header.protocol != 17 and curPacket.IP_header.protocol != 1:
        return None

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
    if trace.source_ip == "":
        trace.source_ip = curPacket.IP_header.src_ip
    if trace.destination_ip == "":
        trace.destination_ip = curPacket.IP_header.dst_ip

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
    global trace
    source_ip = curPacket.IP_header.src_ip
    destination_ip = curPacket.IP_header.dst_ip
    protocol = curPacket.IP_header.protocol
    mf = curPacket.IP_header.mf
    fragment_offset = curPacket.IP_header.fragment_offset
    source_port = curPacket.UDP_header.src_port
    destination_port = curPacket.UDP_header.dst_port
    timestamp = curPacket.timestamp
    type = curPacket.ICMP_header.type

    connection_id = f"{source_ip}-{destination_ip}"
    src_to_dst = f"{destination_ip}-{source_ip}"
    if connection_id not in connections and src_to_dst not in connections:
        connections[connection_id] = Connection()
        connections[connection_id].source_ip = source_ip
        connections[connection_id].destination_ip = destination_ip
        connections[connection_id].source_port = source_port
        connections[connection_id].destination_port = destination_port
        connections[connection_id].start_time = timestamp

    connection = connections[connection_id]
    if (fragment_offset != 0):
        connection.fragment_offset = fragment_offset
        trace.last_offset = fragment_offset
        trace.num_frags += 1
    connection.type = type
    connection.mf = mf
    # connection.end_time = timestamp

    if source_ip == connection.source_ip:
        connection.rtt_end.append(timestamp)

    if (protocol == 1 or protocol == 17):
        connection.protocol = protocol
    if protocol == 1:
        connection.identifier = curPacket.ICMP_header.identifier
        connection.sequence_number = curPacket.ICMP_header.sequence_number


def calculate_output(connections):
    global trace
    original_connection = connections[f"{trace.source_ip}-{trace.destination_ip}"]

    for connection in connections.values():
        rtt = []
        if connection.type == 11:
            trace.intermediate_nodes.append(connection.source_ip)
            for i in range(len(connection.rtt_end)):
                cur_rtt = connection.rtt_end[i] - connection.start_time
                rtt.append(cur_rtt)

            trace.rtt.append(mean(rtt))
            trace.sd.append(std_dev(rtt))

        if connection.protocol not in trace.protocols:
            trace.protocols.append(connection.protocol)

        if connection.mf:
            trace.last_offset = connection.fragment_offset

    # Add the source and destination rtt
    rtt = []
    for i in range(len(original_connection.rtt_end)):
        cur_rtt = original_connection.rtt_end[i] - \
            original_connection.start_time
        rtt.append(cur_rtt)

    print(rtt)
    trace.rtt.append(mean(rtt))
    trace.sd.append(std_dev(rtt))

    if connection.protocol not in trace.protocols:
        trace.protocols.append(connection.protocol)


def print_connection_info(connections):
    protocols = {1: "ICMP",
                 17: "UDP"}

    calculate_output(connections)

    print(f"Source IP: {trace.source_ip}")
    print(f"Destination IP: {trace.destination_ip}")

    print("Intermediate Destination Nodes:")
    for i, node in enumerate(trace.intermediate_nodes, start=1):
        print(f"{i}. {node}")

    print("\nProtocol Values:")
    for protocol in trace.protocols:
        print(f"{protocol}: {protocols[protocol]}")

    print(f"\nNumber of Fragments: {trace.num_frags}")
    print(f"Offset of Last Fragment: {trace.last_offset}")
    print("\n")
    print(len(trace.rtt))
    for i in range(len(trace.rtt)-1):
        print(
            f"The avg RTT between {trace.source_ip} and {trace.intermediate_nodes[i]} is {round(trace.rtt[i] * 1000, 5)} ms, the s.d. is {round(trace.sd[i] * 1000, 5)} ms")
    print(
        f"The avg RTT between {trace.source_ip} and {trace.destination_ip} is {round(trace.rtt[(len(trace.rtt)-1)], 5)} ms, the s.d. is {round(trace.sd[(len(trace.sd )-1)], 5)} ms")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CapReader.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    connections = parse_cap_file(filename)
    print_connection_info(connections)
