import asyncio, binascii
import socket
import fcntl
import packets
import parse
import sys, optparse

ETH_P_IP = 0x0800

def parse_args():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--raw", dest="print_raw_packets",
                      action = "store_true",
                      default = False,
                      help="Hexdump packets to stdout")

    parser.add_option("-a", "--all", dest="print_all_layers",
                      action = "store_true",
                      default = False,
                      help="Dump dissected packets to stdout")

    parser.add_option("-D", "--dump", dest="dump",
                      action = "store_true",
                      default = False,
                      help="Dump all, implies -ra")

    r = parser.parse_args(sys.argv[1:])[0]
    if r.dump:
        r.print_all_layers = True
        r.print_raw_packets = True
    return r 

@asyncio.coroutine
def parse_data(packet, options):
    if options.print_raw_packets:
        packets.print_nice_packet(packet)
    layers = parse.parse(packet, packets.EthLayer) #packets.BasePacket.parse(packet, packets.EthLayer)
    if options.print_all_layers:
        layers.pprint()


@asyncio.coroutine
def wait_data(loop, options):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    while True:
        reader, writer = yield from asyncio.open_connection(sock=s, loop=loop)
        data = yield from reader.read(65565)
        yield from parse_data(data, options)



def main(options):

    loop = asyncio.get_event_loop()
    loop.run_until_complete(wait_data(loop, options))

if __name__ == '__main__':
    main(parse_args())
