import struct, binascii, ctypes, socket
import collections

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
                  value = "".join([i for i in value])
                print("{}+ {}:{}".format(padding, attr_name, value))

    # Static methods
    @staticmethod
    def factorise(cls, data):
        """Create a new packet instance, of type cls, using data as raw packet data."""
        inst = cls()
        ctypes.memmove(ctypes.addressof(inst), data, ctypes.sizeof(cls))
        return inst

    @staticmethod
    def parse(raw_data, beginCls):
        """parse a packet, beginning with an Ethernet Frame"""
        p = BasePacket.factorise(beginCls, raw_data)
        frames = [p]
        while p.next():
            next_packet_type, last_byte = p.next()
            p = next_packet_type.factorise(raw_data[last_byte:])
            frames.append(p)
        return ParsingResult(frames)

class EthLayer(BasePacket, ctypes.BigEndianStructure):
    """Ethernet Layer"""
    _fields_ = (("src", ctypes.c_ushort * 3),
                ("dst", ctypes.c_ushort * 3),
                ("protocol", ctypes.c_ushort))
    _hr_fields_ = list(_fields_)

    def next(self):
        """Decide what king of layer will be parsed next.
        Return a tuple (type, bytes_consumed) or false.
        """
        # next : IPv4 layer
        if self.protocol == 0x0800:
            return IPv4Layer, 14
            
    @staticmethod
    def factorise(data):
        """Instanciate a new Eth instante, using data.
        This function assumes that the layer begin at data[0].
        """
        inst = EthLayer()
        ctypes.memmove(ctypes.addressof(inst), data, ctypes.sizeof(inst))
        return inst


class IPv4Layer(BasePacket, ctypes.BigEndianStructure):
    """IPv4 Layer"""
    _fields_ = (("version", ctypes.c_int),
                ("bIHL", ctypes.c_ubyte * 4),
                ("DSCP", ctypes.c_ubyte * 6),
                ("ECN", ctypes.c_ubyte * 2),
                ("length", ctypes.c_int16))
    @staticmethod
    def factorise(data):
        p = BasePacket.factorise(IPv4Layer, data)

        #take first 20 characters for the ip header
        ip_header = data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', data[0:20])

        version_ihl = iph[0]
        p.version = version_ihl >> 4
        p.IHL = version_ihl & 0xF
        p.length = p.IHL * 4

        ttl = iph[5]
        p.protocol = iph[6]
        p.source_addr = socket.inet_ntoa(iph[8]);
        p.destination_addr = socket.inet_ntoa(iph[9]);
        p._hr_fields_.append(("protocol", None))
        p._hr_fields_.append(("source_addr", None))
        p._hr_fields_.append(("destination_addr", None))
        return p
