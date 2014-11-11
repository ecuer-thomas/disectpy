import struct
import binascii
import socket
import collections
#from filters import filter_ctx, FILTERS

# helpers
def term_printable(ch):
    if (33 <= ch <= 126):
        return ch
    return ord(".")
    
def print_nice_packet(bstr):
    """raw Pretty print a raw_packet"""
    hexvalue = binascii.hexlify(bstr).decode()
    s = [hexvalue[i:i+2] for i in range(0, len(hexvalue), 2)]
    out = []
    for i in range(0, len(bstr), 32):
        out.append(s[i:i+32])
    out.append(s[i + 32:])
    # now, pretty print
    for line in out:
        readable_string = ""
        print(" ".join(line).ljust(96), end="|")
        for i in line:
            ch = term_printable(int(i, 16))
            readable_string += chr(ch)
        print(readable_string)

def dirty_decode_raw_data(data):
    out = ""

    for b in data:
        if 32 <= b <= 126:
            out += chr(b)
        elif b == ord("\n"):
            out += r"\n"
        elif b == ord("\r"):
            out += r"\r"
        else:
            out += "."
    return out

class ParsingResult(list):
    """Simple container for network layers"""
    def pprint(self):
        """pretty print a parsed packet"""
        padding = ""
        for i in self:
            i.pprint(padding)
            padding += "\t"
        print("")

class BasePacket:
    """Basic information about any packets.
    Ancestors of all packets.
    """
    _fields_ = ()

    def __init__(self):
        # _hr_fields_ should not be instance bounded,
        # as it can vary during execution
        self._hr_fields_ = list(self._fields_)

    def next(self, *args, **kwargs):
        """Decide what kind of layer/frame will be parsed next.
        Return a false value if can't parse anything ("terminals/app" layers as HTTP)
        else, return a tuple (type, bytes_consumed)
        """
        return False

    def pprint(self, padding="", *args, **kwargs):
        print("{}< Layer [{}] >".format(padding, str(type(self).__name__)))
        if hasattr(self, '_hr_fields_'):
            for attr_name, item_type in self._hr_fields_:
                value = getattr(self, attr_name)
                if isinstance(value, collections.Iterable):
                    value = "".join([str(i) for i in value])
                if attr_name == "protocol" and value == 6:
                    value = "6 (TCP)"
                if attr_name == "protocol" and value == 0x0800:
                    value = "4"

                print("{}+ {} : {}".format(padding, attr_name, value))

    # Static methods
    @staticmethod
    def factorise(cls, data):
        """Create a new packet instance, of type cls, using data as raw packet data."""
        inst = cls.factorise(data)
        return inst

    @staticmethod
    def parse(raw_data, beginCls):
        """parse a packet.
        params : 
        :raw_data: packet's bytes"""
        frames = []
        consumed = 0
        with filters.filter_ctx():
            p = BasePacket.factorise(beginCls, raw_data)
            frames += [p]
            #[f(frames[0]) for f in FILTERS]
            while p.next():
                next_packet_type, last_byte = p.next()
                consumed += last_byte
                p = next_packet_type.factorise(raw_data[consumed:])
                frames.append(p)
                [f(p) for f in filters.FILTERS]

        return ParsingResult(frames)

class EthLayer(BasePacket):
    """Ethernet Layer"""
    _fields_ = (("src", None),
                ("dst", None),
                ("protocol", None))

    def next(self):
        """Decide what king of layer will be parsed next.
        Return a tuple (type, bytes_consumed) or false.
        """
        # next : IPv4 layer
        if self.protocol == 0x0800:
            return IPv4Layer, 14
        return False
            
    @staticmethod
    def factorise(data):
        """Instanciate a new Eth instante, using data.
        This function assumes that the layer begin at data[0].
        """
        inst = EthLayer()

        header = struct.unpack('!6B6BH', data[0:14])
        hex_src_mac = binascii.hexlify(bytes(header[0:6])).decode()
        hex_dst_mac = binascii.hexlify(bytes(header[6:12])).decode()

        inst.src = ":".join([hex_src_mac[i:i+2] for i in range(0, 12, 2)])
        inst.dst = ":".join([hex_dst_mac[i:i+2] for i in range(0, 12, 2)])
        inst.protocol = header[12]

        return inst

class IPLayer(BasePacket):
    pass

class IPv4Layer(IPLayer):
    """IPv4 Layer"""
    _fields_ = (("version", None),
                ("IHL", None),
                ("TTL", None),
                ("protocol", None),
                ("source_addr", None),
                ("dest_addr", None))
    @staticmethod
    def factorise(data):
        """Create a new IPv4 Layer using data.
        """
        p = IPv4Layer()

        #take first 20 characters for the ip header
        ip_header = data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', data[0:20])

        version_ihl = iph[0]
        p.version = version_ihl >> 4
        p.IHL = version_ihl & 0xF
        p.length = p.IHL * 4

        p.TTL = iph[5]
        p.protocol = iph[6]
        p.source_addr = socket.inet_ntoa(iph[8]);
        p.dest_addr = socket.inet_ntoa(iph[9]);
        return p

    def next(self):
        """
        """
        # see RFC790 : http://tools.ietf.org/html/rfc790
        # TCP(6)
        if self.protocol == 6:
            # TCP(6)
            return TCPLayer, self.length
        elif self.protocol == 17:
            # UDP(17)
            return UDPLayer, self.length
        return False

class TCPLayer(BasePacket):
    """TCP Layer"""
    _fields_ = (("source_port", None),
                ("dest_port", None),
                ("sequence", None),
                ("acknowledgement", None),
                ("doff_reserved", None),
                ("header_length", None),
                ("h_size", None),
                ("data_size", None),
                ("data", None))

    @staticmethod
    def factorise(data):
        """Create a new TCP Layer using data.
        """
        p = TCPLayer()

        tcp_header = data[0:20]

        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

        p.source_port = tcph[0]
        p.dest_port = tcph[1]
        p.sequence = tcph[2]
        p.acknowledgement = tcph[3]
        p.doff_reserved = tcph[4]
        p.header_length = p.doff_reserved >> 4
        p.h_size = p.header_length * 4
        p.data_size = len(data) - p.h_size

        #get data from the packet
        p.data = dirty_decode_raw_data(data[p.h_size:])
        return p

    def next(self):
        """
        """
        return False

class UDPLayer(BasePacket):
    """UDP Layer"""
    _fields_ = (("source_port", None),
                ("dest_port", None),
                ("length", None),
                ("checksum", None),
                ("data", None))

    @staticmethod
    def factorise(data):
        """Create a new UDP Layer using raw data.
        """
        p = UDPLayer()
        udp_header = data[0:8]
        p.source_port, p.dest_port, p.length, p.checksum = struct.unpack("!HHHH", udp_header)
        p.data = dirty_decode_raw_data(data[8:])
        return p

    def next(self):
        """
        """
        return False

