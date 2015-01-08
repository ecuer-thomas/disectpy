import filters
import packets
import conf

def parse(raw_data, beginCls, continuations):
    """parse a packet.
    params : 
    :raw_data: packet's bytes"""
    frames = []
    consumed = 0
    with filters.filter_ctx():

        # Dissect first Layer
        p = packets.BaseLayer.factorise(beginCls, raw_data)
        frames += [p]
        [f(frames[0]) for f in conf.FILTERS]

        # Dissect subjacent layer
        while p.next():
            next_packet_type, last_byte = p.next()
            consumed += last_byte
            p = next_packet_type.factorise(raw_data[consumed:],
                                           previous=p,
                                           continuations=continuations)
            frames.append(p)
            [f(p) for f in conf.FILTERS]
 
    return packets.ParsingResult(frames), continuations


def coparse(raw_data, beginCls):
    """old parsing function without filtering"""
    frames = []
    consumed = 0
    with filters.filter_ctx():

        # Dissect first Layer
        p = packets.BaseLayer.factorise(beginCls, raw_data)
        frames += [p]
        [f(frames[0]) for f in filters.FILTERS]

        # Dissect subjacent layers
        while p.next():
            next_packet_type, last_bytes = p.next()
            consumed += last_bytes
            p = next_packet_type.factorise(raw_data[consumed:])
            frames.append(p)
            [f(p) for f in filters.FILTERS]


    return packets.ParsingResult(frames)
