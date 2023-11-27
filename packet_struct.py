import struct


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    protocol = None  # <type 'int'>
    fragment_offset = None  # <type 'int'>
    mf = False  # <type 'bool'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.' + \
            str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.' + \
            str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        # print(f"IHL: {length}")
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        length = num1+num2+num3+num4
        # print(f"Total Length: {length}")
        self.total_len_set(length)

    def get_protocol(self, protocol_bytes):
        self.protocol = struct.unpack('B', protocol_bytes)[0]

    def get_fragment_offset(self, flags_and_offset_bytes):
        """
        Extracts and sets the fragment offset field in the IP header.

        Parameters:
        - flags_and_offset_bytes (bytes): The bytes representing the flags and offset fields in the IP header.
        """
        flags_and_offset = struct.unpack('>H', flags_and_offset_bytes)[0]
        # Extract the last 13 bits (fragment offset)
        self.fragment_offset = flags_and_offset & 0x1FFF

    def get_more_fragments(self, flags_and_offset_bytes):
        """
        Extracts and sets the more fragments field in the IP header.

        Parameters:
        - flags_and_offset_bytes (bytes): The bytes representing the flags and offset fields in the IP header.
        """
        flags_and_offset = struct.unpack('>H', flags_and_offset_bytes)[0]
        # Check the 14th bit (more fragments)
        self.more_fragments = (flags_and_offset & 0x2000) != 0


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        # print(f"SRC PORT: {self.src_port}")
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        # print(f"DST PORT: {self.dst_port}")
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        # print(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack('>I', buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        # print(self.flags)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H', buffer)[0]
        self.win_size_set(size)
        # print(f"Window Size: {size}")
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4)*4
        self.data_offset_set(length)
        # print(f"OFFSET: {self.data_offset}")
        return None

    def relative_seq_num(self, orig_num):
        if (self.seq_num >= orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        # print(self.seq_num)

    def relative_ack_num(self, orig_num):
        if (self.ack_num >= orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)


class packet():

    # pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    num_frags = 0

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        # self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def timestamp_set(self, buffer1, buffer2, orig_time, ms):
        seconds = struct.unpack('I', buffer1)[0]
        microseconds = struct.unpack('<I', buffer2)[0]
        if ms:
            self.timestamp = round(seconds+microseconds*0.000001-orig_time, 6)
        else:
            self.timestamp = round(
                seconds+microseconds*0.000000001-orig_time, 6)
        # print(f"Timestamp: {self.timestamp} packet #: {self.packet_No}")

    def packet_No_set(self, number):
        self.packet_No = number
        # print(self.packet_No)

    def get_RTT_value(self, p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt, 8)


class Connection:
    def __init__(self):
        self.source_ip = ""
        self.destination_ip = ""
        self.source_port = 0
        self.destination_port = 0
        self.window_size_src = 0
        self.window_size_dst = 0
        self.total_window_size = 0
        self.start_time = 0
        self.end_time = 0
        self.packets_source_to_dest = 0
        self.packets_dest_to_source = 0
        self.data_bytes_source_to_dest = 0
        self.data_bytes_dest_to_source = 0
        self.fin_num = 0
        self.syn_num = 0
        self.rst_num = 0
        self.expected_ack = 0
        self.rtt_start = []
        self.rtt_end = []
        self.rtt_num = 0
        self.rtt = []
        self.inter_nodes = []
        self.num_frags = 0
        self.protocols = []
        self.fragment_offset = 0
