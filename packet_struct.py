import struct


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    protocol = None  # <type 'int'>
    fragment_offset = None  # <type 'int'>
    mf = False  # <type 'bool'>
    ttl = None  # <type 'int'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def ttl_set(self, ttl):
        self.ttl = ttl

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
        flags_and_offset = struct.unpack('>H', flags_and_offset_bytes)[0]
        # Extract the last 13 bits (fragment offset)
        self.fragment_offset = (flags_and_offset & 0x1FFF) * 8

    def get_more_fragments(self, flags_and_offset_bytes):
        flags_and_offset = struct.unpack('>H', flags_and_offset_bytes)[0]
        # Check the 14th bit (more fragments)
        self.mf = (flags_and_offset & 0x2000) != 0

    def get_ttl(self, ttl_byte):
        self.ttl = struct.unpack('B', ttl_byte)[0]


class UDP_Header:
    src_port = None  # <type 'int'>
    dst_port = None  # <type 'int'>
    length = None  # <type 'int'>
    checksum = None  # <type 'int'>

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.length = 0
        self.checksum = 0

    def src_port_set(self, port):
        self.src_port = port

    def dst_port_set(self, port):
        self.dst_port = port

    def length_set(self, length):
        self.length = length

    def checksum_set(self, checksum):
        self.checksum = checksum

    def get_UDP(self, buffer):
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', buffer)
        self.src_port_set(src_port)
        self.dst_port_set(dst_port)
        self.length_set(length)
        self.checksum_set(checksum)


class ICMP_Header:
    type = None  # <type 'int'>
    code = None  # <type 'int'>
    checksum = None  # <type 'int'>
    identifier = None  # <type 'int'>
    sequence_number = None  # <type 'int'>

    def __init__(self):
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.identifier = 0
        self.sequence_number = 0

    def type_set(self, icmp_type):
        self.type = icmp_type

    def code_set(self, icmp_code):
        self.code = icmp_code

    def checksum_set(self, checksum):
        self.checksum = checksum

    def identifier_set(self, identifier):
        self.identifier = identifier

    def sequence_number_set(self, sequence_number):
        self.sequence_number = sequence_number

    def get_ICMP(self, buffer):
        icmp_type, icmp_code, checksum, identifier, sequence_number = struct.unpack(
            '!BBHHH', buffer)
        self.type_set(icmp_type)
        self.code_set(icmp_code)
        self.checksum_set(checksum)
        self.identifier_set(identifier)
        self.sequence_number_set(sequence_number)


class packet():
    IP_header = None
    ICMP_header = None
    UDP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    num_frags = 0
    hops_info = []

    def __init__(self):
        self.IP_header = IP_Header()
        self.ICMP_header = ICMP_Header()
        self.UDP_header = UDP_Header()
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


def mean(values):
    return sum(values) / len(values)


def std_dev(values):
    avg = mean(values)
    return (sum([(x - avg)**2 for x in values]) / len(values))**0.5


class Connection:
    def __init__(self):
        self.packets = []
        self.source_ip = ""
        self.destination_ip = ""
        self.source_port = 0
        self.destination_port = 0
        self.start_time = 0
        self.end_time = 0
        self.rtt_start = []
        self.rtt_end = []
        self.rtt_num = 0
        self.rtt = []
        self.mf = 0
        self.num_frags = 0
        self.protocol = 0
        self.fragment_offset = 0
        self.ttl = -1
        self.type = 0
        self.identifier = 0  # <type 'int'>
        self.sequence_number = 0  # <type 'int'>
        self.hops = []


class Traceroute:
    def __init__(self):
        self.source_ip = ""
        self.destination_ip = ""
        self.intermediate_nodes = []
        self.protocols = []
        self.num_frags = 0
        self.last_offset = 0
        self.avg_rtt = []
        self.sd = []
