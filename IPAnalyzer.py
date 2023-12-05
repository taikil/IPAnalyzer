from packet_struct import *
import struct
import sys
from collections import defaultdict
import statistics as s

trace = Traceroute()
ICMP = 1
UDP = 17
ms = True
orig_time = 0


def parse_cap_file(filename):
    global ms
    global orig_time
    with open(filename, 'rb') as file:

        global_header = file.read(24)
        magic_number, _, _, _, _, _, _ = struct.unpack(
            "IHHIIII", global_header)

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
            curPacket = parse_packet(buffer, packet_header)
            if curPacket == None:
                packet_header = file.read(16)
                continue

            # Move to next packet
            packet_header = file.read(16)


def parse_packet(buffer, packet_header):
    global trace
    global ms
    global orig_time

    curPacket = packet()
    curPacket.timestamp_set(
        packet_header[0:4], packet_header[4:8], orig_time, ms)
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

    # If UDP
    if curPacket.IP_header.protocol == UDP:
        # First 8 bytes of TCPHeader
        udp_buffer = buffer[i:i+8]
        i += 8
        if trace.os == None:
            trace.os = "Linux"
        curUDP = UDP_Header()
        curUDP.get_UDP(udp_buffer)
        # Unwanted
        if curUDP.dst_port < 33434 or curUDP.dst_port > 33529:
            return None
        curPacket.UDP_header = curUDP
        trace.hops.append((curPacket.IP_header.ttl,
                          curPacket.UDP_header.src_port, curPacket.timestamp))
        if UDP not in trace.protocols:
            trace.protocols.append(UDP)
    # ICMP
    elif curPacket.IP_header.protocol == ICMP:
        icmp_buffer = buffer[i:]
        curICMP = ICMP_Header()
        curICMP.get_ICMP(icmp_buffer)
        curPacket.ICMP_header = curICMP
        if curICMP.type == 8 or curICMP.type == 3:
            if trace.os == None:
                trace.os == "Windows"
            trace.hops.append((curPacket.IP_header.ttl,
                              curPacket.ICMP_header.identification, curPacket.timestamp))
        else:
            if trace.os == "Windows":
                identification = curPacket.ICMP_header.identification
            if trace.os == "Linux":
                identification = curPacket.ICMP_header.source_port

            for hop in trace.hops:
                print(hop)
                print(curPacket.IP_header.src_ip)
                print(identification)
                if hop[1] == identification:
                    if curPacket.IP_header.src_ip not in trace.rtt.keys():
                        trace.rtt[curPacket.IP_header.src_ip] = [
                            curPacket.timestamp-hop[2]]
                    else:

                        temp = trace.rtt[curPacket.IP_header.src_ip]
                        temp.append(curPacket.timestamp-hop[2])
                        trace.rtt[curPacket.IP_header.src_ip] = temp

                    if curPacket.IP_header.src_ip not in trace.intermediate_nodes.keys():
                        offset = 0.0
                        while hop[0] + offset in trace.intermediate_nodes.values():
                            offset += 1

                        trace.intermediate_nodes[curPacket.IP_header.src_ip] = hop[0] + offset
        if 1 not in trace.protocols:
            trace.protocols.append(1)

    else:
        return None

    if curPacket.IP_header.identification not in trace.frags.keys():
        trace.frags[curPacket.IP_header.identification] = (
            trace.num_frags, 1, 0)
        trace.num_frags += 1

    if trace.offset != 0 and curPacket.IP_header.identification in trace.frags.keys():
        trace.frags[curPacket.IP_header.identification] = (
            trace.frags[curPacket.IP_header.identification][0], trace.frags[curPacket.IP_header.identification][1]+1, trace.offset*8)

    if trace.os == "Windows":
        identification = curPacket.ICMP_header.identification
    if trace.os == "Linux":
        identification = curPacket.ICMP_header.source_port

    check_hops(curPacket, identification)

    if trace.source_ip == "":
        trace.source_ip = curPacket.IP_header.src_ip
    if trace.destination_ip == "":
        trace.destination_ip = curPacket.IP_header.dst_ip

    if curPacket.IP_header.fragment_offset > 0:
        trace.offset = curPacket.IP_header.fragment_offset
        trace.num_frags += 1

    return curPacket


def get_IP_info(curPacket, ip_header_buffer):
    curPacket.IP_header.get_header_len(ip_header_buffer[0:1])
    curPacket.IP_header.get_total_len(ip_header_buffer[2:4])
    curPacket.IP_header.get_identification(ip_header_buffer[4:6])
    curPacket.IP_header.get_fragment_offset(ip_header_buffer[6:8])
    curPacket.IP_header.get_more_fragments(ip_header_buffer[6:8])
    curPacket.IP_header.get_ttl(ip_header_buffer[8:9])
    curPacket.IP_header.get_protocol(ip_header_buffer[9:10])
    curPacket.IP_header.get_IP(
        ip_header_buffer[12:16], ip_header_buffer[16:20])


def check_hops(curPacket, id):
    for hop in trace.hops:
        print(hop)
        print(curPacket.IP_header.dst_ip)
        print(id)
        if hop[1] == id:
            if curPacket.IP_header.src_ip not in trace.rtt.keys():
                trace.rtt[curPacket.IP_header.src_ip] = [
                    curPacket.timestamp-hop[2]]
            else:

                temp = trace.rtt[curPacket.IP_header.src_ip]
                temp.append(curPacket.timestamp-hop[2])
                trace.rtt[curPacket.IP_header.src_ip] = temp

            if curPacket.IP_header.src_ip not in trace.intermediate_nodes.keys():
                offset = 0.0
                while hop[0] + offset in trace.intermediate_nodes.values():
                    offset += 1

                trace.intermediate_nodes[curPacket.IP_header.src_ip] = hop[0] + offset


def reorder_output():
    global trace

    print("Intermediate: ", len(trace.intermediate_nodes))
    # for k, v in trace.intermediate_nodes.items():
    #     print("KV", k, v)
    # end_node = trace.intermediate_nodes[trace.destination_ip]
    # trace.intermediate_nodes.pop(trace.destination_ip)
    # for k, v in trace.intermediate_nodes.items():
    #     if v > end_node:
    #         trace.intermediate_nodes[k] = v - 1


def print_connection_info():
    global trace

    protocols = {1: "ICMP",
                 17: "UDP"}
    ordered = [(k, v) for k, v in sorted(
        trace.intermediate_nodes.items(), key=lambda x: x[1])]

    reorder_output()

    print(f"Source IP: {trace.source_ip}")
    print(f"Destination IP: {trace.destination_ip}")

    print("Intermediate Destination Nodes:")
    for i, node in enumerate(ordered, start=1):
        print(f"{i}. {node[0]}")

    print("\nProtocol Values:")
    for protocol in trace.protocols:
        print(f"{protocol}: {protocols[protocol]}")

    print(f"\nNumber of Fragments: {trace.num_frags}")
    print(f"Offset of Last Fragment: {trace.offset}")
    print("\n")

    if trace.num_frags > 1:
        for fragment in trace.frags.values():
            print(
                f"The number of fragments created from the original datagram D{fragment[0]} is: {fragment[1]}")
            print(f"The offset of the last fragment is: {fragment[2]}")
        print("\n")
    for k, v in ordered:
        print(
            f"The avg RTT between {trace.source_ip} and {k} is {round(mean(trace.rtt[k]) * 1000, 5)} ms, the s.d. is {round(std_dev(trace.rtt[k]) * 1000, 5)} ms")
    print(
        f"The avg RTT between {trace.source_ip} and {trace.destination_ip} is {round(trace.rtt[trace.destination_ip] * 1000, 5)} ms, the s.d. is {round(std_dev(trace[trace.destination_ip]), 5)} ms")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CapReader.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    parse_cap_file(filename)
    print_connection_info()
