import asyncio, binascii
import socket
import fcntl
import packets
import parse
import sys, optparse
import concurrent.futures
import conf

ETH_P_IP = 0x0800

def parse_args():
    parser = optparse.OptionParser(usage="usage %prog [options] [...arguments]",
                                   epilog="without arguments, the analyser behaviour is driven bye filters")
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

#@asyncio.coroutine
def parse_data(loop, packet, options, continuations):
    if continuations == None:
        continuations = {}

    layers, continuations = parse.parse(packet,
                                        packets.EthLayer,
                                        continuations)



    if options.print_raw_packets:
        packets.print_nice_packet(packet)

    if options.print_all_layers:
        layers.pprint()


@asyncio.coroutine
def wait_data(loop, options):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    continuations = {}

    while True:
        
        reader, writer = yield from asyncio.open_connection(sock=s, loop=loop)
        data = yield from reader.read(65565)
        #yield from parse_data(loop, data, options, continuations)

        # delay work in a thread pool
        loop.run_in_executor(None, parse_data, loop, data, options, continuations)


def main(options):

    loop = asyncio.get_event_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=conf.THREADS))
    try:
        
        loop.run_until_complete(wait_data(loop, options))
    except KeyboardInterrupt:
        print("\rBye.")
        exit(0)

if __name__ == '__main__':
    main(parse_args())
