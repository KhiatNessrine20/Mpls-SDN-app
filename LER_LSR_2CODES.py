from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, mpls

class MPLS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MPLS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.label = 16
        self.dst_to_label = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Parse the packet data.
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        mpls_proto = pkt.get_protocol(mpls.mpls)
        dst = eth.dst
        ethtype = eth.ethertype
        # The switch can be a LSR or a LER, but the match is the same
        # Set the out_port using the relation learnt with the ARP packet 
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        # Check if the packet is an IP packet.
        if ethtype == ether.ETH_TYPE_IP:
            # Handle IP packets here.
            # Switch labels
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            src
                self.add_flow(datapath, 1, match, actions)

        # Check if the packet is a VLAN packet.
        elif eth.ethertype == ether.ETH_TYPE_8021Q:
            # Handle VLAN packets here.
            # ...
            pass

        # Check if the packet is an ARP packet.
        elif eth.ethertype == ether.ETH_TYPE_ARP:
            # Handle ARP packets here.
            # ...
            pass

        # If the packet is none of the above, drop the packet.
        else:
            self.logger.info("Packet with unsupported ethertype %s received", hex(ethtype))
            return

        # Send the packet out to the specified port.
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

        ///////
# Set the out_port using the relation learnt with the ARP packet 
out_port = self.mac_to_port[dpid][dst]

# Prepare the actions list to output the packet to the destination port.
actions = [parser.OFPActionOutput(out_port)]
/////////////
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, packet, mpls, ipv4, tcp

class MyMPLSApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyMPLSApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.label_table = {} # store label-to-outport mapping
        self.switches = {} # store switch-to-inport mapping

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # extract necessary information from packet
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # handle LER functionality
        if self.is_ler(datapath.id):
            # look for MPLS label
            mpls_pkt = pkt.get_protocol(mpls.mpls)
            if mpls_pkt:
                label = mpls_pkt.label
                if label in self.label_table:
                    # swap MPLS label and output packet
                    out_port = self.label_table[label]
                    actions = [parser.OFPActionPopMpls(),
                               parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, 1, parser.OFPMatch(in_port=in_port,
                                    eth_type=0x8847, mpls_label=label),
                                    actions, msg.buffer_id)
                    # send packet out
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=msg.buffer_id,
                                              in_port=in_port,
                                              actions=actions)
                    datapath.send_msg(out)
                    return

            # handle other packets normally
            dst = eth.dst
            src = eth.src

            # learn MAC address to avoid FLOOD next time.
            self.mac_to_port.setdefault(datapath
