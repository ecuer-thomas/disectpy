import asyncio, binascii
import socket
import fcntl
import packets

@asyncio.coroutine
def handle_packet(client, addr):
    pass

@asyncio.coroutine
def handle_packets(sock):
    while True:
        packet, address = sock.recvfrom(65565, 0)
        print("#" * 96)
        packets.print_nice_packet(packet)
        p = packets.BasePacket.factorise(packets.EthLayer, packet)
        layers = packets.BasePacket.parse(packet, packets.EthLayer)
        layers.pprint()



ETH_P_IP = 0x0800

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(handle_packets(s))

if __name__ == '__main__':
    main()
