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

        bigEndian = True

        if magic_number == 0xa1b2c3d4:
            print("Valid PCAP file detected.")
        elif magic_number == 0xd4c3b2a1:
            print("Reverse bytes")
            bigEndian = False
        else:
            print("Invalid PCAP file format.")
            return

        orig_time = 0
        packet_number = 1
        
        packet_header = file.read(16)
        # Get Timestamp of first packet
        if (bigEndian):
            orig_time = struct.unpack('I', packet_header[0:4])[0] + (struct.unpack('<I', packet_header[4:8])[0]*0.000001)
        else:
            orig_time = struct.unpack('I', packet_header[0:4])[0] + (struct.unpack('>I', packet_header[4:8])[0]*0.000001)



        while file.readable:
            if not packet_header:
                break

            curPacket = packet()
            curPacket.packet_No_set(packet_number)
            curPacket.timestamp_set(
                packet_header[0:4], packet_header[4:8], orig_time)

            _, _, incl_len, _ = struct.unpack('IIII', packet_header)

            # Ethernet Header
            _ = file.read(14)

            # First 20 bytes of IPHEADER
            ip_header_buffer = file.read(20)
            get_IP_info(curPacket, ip_header_buffer)

            # If IP Header is longer than 20 bytes
            if curPacket.IP_header.ip_header_len > 20:
                _ = file.read(curPacket.IP_header.ip_header_len - 20)

            # First 20 bytes of TCPHeader
            tcp_header_buffer = file.read(20)
            get_TCP_info(curPacket, tcp_header_buffer)

            # Read  TCPHeader options 
            if curPacket.TCP_header.data_offset > 20:
                _ = file.read(curPacket.TCP_header.data_offset - 20)

            # Read the rest of the payload
            payload_len = incl_len - (14 + curPacket.TCP_header.data_offset +
                                      curPacket.IP_header.ip_header_len)
            bytes_len = curPacket.IP_header.total_len - curPacket.TCP_header.data_offset - curPacket.IP_header.ip_header_len 
            _ = file.read(payload_len)
            process_packet(bytes_len,
                           curPacket, connections)
            
            # Move to next packet
            packet_number += 1
            packet_header = file.read(16)

    return connections


def get_IP_info(curPacket, ip_header_buffer):
    curPacket.IP_header.get_IP(
        ip_header_buffer[12:16], ip_header_buffer[16:20])
    curPacket.IP_header.get_header_len(ip_header_buffer[0:1])
    curPacket.IP_header.get_total_len(ip_header_buffer[2:4])


def get_TCP_info(curPacket, tcp_header_buffer):
    curPacket.TCP_header.get_src_port(tcp_header_buffer[0:2])
    curPacket.TCP_header.get_dst_port(tcp_header_buffer[2:4])
    curPacket.TCP_header.get_seq_num(tcp_header_buffer[4:8])
    curPacket.TCP_header.get_ack_num(tcp_header_buffer[8:12])
    curPacket.TCP_header.get_data_offset(tcp_header_buffer[12:13])
    curPacket.TCP_header.get_flags(tcp_header_buffer[13:14])
    curPacket.TCP_header.get_window_size(
        tcp_header_buffer[14:15], tcp_header_buffer[15:16])


def process_packet(payload_len, curPacket, connections):
    source_ip = curPacket.IP_header.src_ip
    destination_ip = curPacket.IP_header.dst_ip
    source_port = curPacket.TCP_header.src_port
    destination_port = curPacket.TCP_header.dst_port
    timestamp = curPacket.timestamp

    connection_id = f"{source_ip}:{source_port}-{destination_ip}:{destination_port}"
    src_to_dst = f"{destination_ip}:{destination_port}-{source_ip}:{source_port}" 
    if connection_id not in connections and src_to_dst not in connections:
        connections[connection_id] = Connection()
        connections[connection_id].source_ip = source_ip
        connections[connection_id].destination_ip = destination_ip
        connections[connection_id].source_port = source_port
        connections[connection_id].destination_port = destination_port
        connections[connection_id].start_time = timestamp

    if src_to_dst in connections:
        connection = connections[src_to_dst]
    else:
        connection = connections[connection_id]

    # Get Flags Data
    if curPacket.TCP_header.flags["SYN"] == 1:
        connection.syn_num += 1 
    if curPacket.TCP_header.flags["FIN"] == 1:
        connection.fin_num += 1
        connection.end_time = timestamp
    if curPacket.TCP_header.flags["RST"] == 1:
        connection.rst_num += 1


    # Update packet and data counts based on packet direction
    if source_ip == connection.source_ip and source_port == connection.source_port:
        connection.packets_source_to_dest += 1
        connection.data_bytes_source_to_dest += payload_len
        connection.window_size_src = curPacket.TCP_header.window_size
        if curPacket.TCP_header.flags["RST"] == 0 and payload_len != 0:
            connection.expected_ack = curPacket.TCP_header.seq_num + payload_len
            connection.rtt_start.append(curPacket.timestamp)
    else:
        connection.packets_dest_to_source += 1
        connection.data_bytes_dest_to_source += payload_len
        connection.window_size_dst = curPacket.TCP_header.window_size
        if curPacket.TCP_header.ack_num == connection.expected_ack:
            connection.rtt_end.append(curPacket.timestamp)
            connection.expected_ack = -1

def calculate_general_statistics(connections):
    total_complete_connections = 0
    reset_connections = 0
    open_connections = 0

    min_duration = float('inf')
    max_duration = 0
    total_duration = 0

    min_rtt = float('inf')
    max_rtt = 0
    rtt = []
    total_rtt = 0

    min_packets = float('inf')
    max_packets = 0
    total_packets = 0

    min_window_size = float('inf')
    max_window_size = 0
    mean_window_size = 0

    for connection in connections.values():
        if connection.packets_source_to_dest > 0 and connection.packets_dest_to_source > 0:
            # Reset Connections
            if connection.rst_num > 0:
                reset_connections += 1
            # Complete Connections
            if connection.fin_num != 0:
                total_complete_connections += 1
                duration = connection.end_time - connection.start_time
                packets = connection.packets_source_to_dest + connection.packets_dest_to_source
                window_size_s = connection.window_size_src
                window_size_d = connection.window_size_dst

                if duration < min_duration:
                    min_duration = duration
                if duration > max_duration:
                    max_duration = duration
                total_duration += duration

                for i in range(len(connection.rtt_end)):
                    cur_rtt = connection.rtt_end[i] -  connection.rtt_start[i]
                    connection.rtt_num += 1
                    total_rtt += cur_rtt
                    rtt.append(cur_rtt)


                if packets < min_packets:
                    min_packets = packets
                if packets > max_packets:
                    max_packets = packets
                total_packets += packets

                if window_size_s < min_window_size:
                    min_window_size = window_size_s
                if window_size_s > max_window_size:
                    max_window_size = window_size_s
                mean_window_size += window_size_s

                if window_size_d < min_window_size:
                    min_window_size = window_size_d
                if window_size_d > max_window_size:
                    max_window_size = window_size_d
                mean_window_size += window_size_d
            # No Fin Flag
            else:
                open_connections += 1

            min_rtt = min(rtt)
            max_rtt = max(rtt)
            mean_rtt = total_rtt/len(rtt) 
            

    return total_complete_connections, reset_connections, open_connections, min_duration, max_duration, total_duration, min_rtt, max_rtt, mean_rtt, min_packets, max_packets, total_packets, min_window_size, max_window_size, mean_window_size


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CapReader.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    connections = parse_cap_file(filename)
