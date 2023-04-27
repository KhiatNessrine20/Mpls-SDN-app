from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, mpls

class LER(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LER, self).__init__(*args, **kwargs)

    # This method will be called when Ryu connects to the switch.
    # It will install the table-miss flow entry on the switch so
    # that packets that don't match any flow entry will be sent
    # to the controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # This method will be called whenever a packet arrives at the switch.
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

        # Check if the packet is an IP packet.
        if eth.ethertype == ether.ETH_TYPE_IP:
            # TODO: Handle IP packets here.
            pass
        # Check if the packet is an MPLS packet.
        elif eth.ethertype == ether.ETH_TYPE_MPLS:
            # Get the MPLS label from the packet.
            mpls_pkt = pkt.get_protocols(mpls.mpls)[0]
            mpls_label = mpls_pkt.label

            # Prepare the new MPLS label to be pushed onto the packet.
            new_mpls_label = 20

            # Create the MPLS header with the new label.
            new_mpls = mpls.mpls(label=new_mpls_label, ttl=64)

            # Insert the MPLS header into the packet.
            pkt.insert(0, new_mpls)

            # Update the Ethernet header.
            eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
            eth_pkt.ethertype = ether.ETH_TYPE_MPLS

            # Prepare the actions to push the new MPLS label.
            actions = [parser.OFPActionPushMpls(ether.ETH_TYPE_MPLS),
                       parser.OFPActionSetField(mpls_label=new_mpls_label),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]

            # Send the actions to the switch to push the new MPLS label.
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=pkt.data)
            datapath.send_msg(out)
