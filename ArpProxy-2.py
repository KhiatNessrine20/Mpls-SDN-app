    

class SimpleARPProxy13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]



    def __init__(self, *args, **kwargs):
        super(SimpleARPProxy13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}    
    
    def packetInHandler():
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src




    def arp_handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            hwtype = arp_pkt.hwtype
            proto = arp_pkt.proto
            hlen = arp_pkt.hlen
            plen = arp_pkt.plen
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet( ethertype=eth.ethertype, dst=eth_src, src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac=self.arp_table[arp_dst_ip],src_ip=arp_dst_ip, dst_mac=eth_src,dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(datapath=datapath,  buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False
