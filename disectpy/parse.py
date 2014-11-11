import filters
import packets


def parse(raw_data, beginCls):
    """parse a packet.
    params : 
    :raw_data: packet's bytes"""
    frames = []
    consumed = 0
    with filters.filter_ctx():
        p = packets.BaseLayer.factorise(beginCls, raw_data)
        frames += [p]
        [f(frames[0]) for f in filters.FILTERS]
        while p.next():
            next_packet_type, last_byte = p.next()
            consumed += last_byte
            p = next_packet_type.factorise(raw_data[consumed:])
            frames.append(p)
            [f(p) for f in filters.FILTERS]

    return packets.ParsingResult(frames)
