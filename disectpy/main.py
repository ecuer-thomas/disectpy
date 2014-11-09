import asyncio, binascii
import socket
import fcntl
import packets

ETH_P_IP = 0x0800

@asyncio.coroutine
def handle_packets(sock):
    while True:
        packet, address = sock.recvfrom(65565, 0)
        print("#" * 96)
        packets.print_nice_packet(packet)
        p = packets.BasePacket.factorise(packets.EthLayer, packet)
        layers = packets.BasePacket.parse(packet, packets.EthLayer)
        layers.pprint()


@asyncio.coroutine
def parse_data(packet):
    packets.print_nice_packet(packet)
    p = packets.BasePacket.factorise(packets.EthLayer, packet)
    layers = packets.BasePacket.parse(packet, packets.EthLayer)
    layers.pprint()


@asyncio.coroutine
def wait_data(loop):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    while True:
        reader, writer = yield from asyncio.open_connection(sock=s, loop=loop)
        data = yield from reader.read(65565)
        yield from parse_data(data)



def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(handle_packets(s))

def main2():

    loop = asyncio.get_event_loop()
    loop.run_until_complete(wait_data(loop))

if __name__ == '__main__':
    main2()
