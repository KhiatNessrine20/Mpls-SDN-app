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

    # This method will be called when Ryu connects to the switch.
    # It will install the table-miss flow entry on the switch so
    # that packets that don't match any flow entry will be sent
    # to the controller.
    #@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    #def switch_features_handler(self, ev):
        #datapath = ev.msg.datapath
        #ofproto = datapath.ofproto
        #parser = datapath.ofproto_parser

        # Install the table-miss flow entry.
        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
         #                                 ofproto.OFPCML_NO_BUFFER)]
       # self.add_flow(datapath, 0, match, actions)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
      datapath = ev.msg.datapath
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser
      match = parser.OFPMatch()
      actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
      self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id= None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser 
        inst =[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
             mod = parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst) 
        datapath.send_msg(mod)

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
        dpid = datapath.id
        mpls_proto = pkt.get_protocol(mpls.mpls)
        dst  = eth.dst
        #src = eth.src     
        ethtype = eth.ethertype
        # The switch can be a LSR or a LER, but the match is the same
            # Set the out_port using the relation learnt with the ARP packet 
        out_port = self.mac_to_port[dpid][dst]
        

        # Check if the packet is an IP packet.
        if eth.ethe == ether.ETH_TYPE_IP:
            # Handle IP packets here.
            # Switch labels 
                src_ip = ipv4_pkt.src
                dst_ip = ipv4_pkt.dst
                self.dst_to_label[dpid][dst] = self.label 
                self.label = self.label + 1
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype)
                actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=self.label), parser.OFPActionOutput(out_port)]
                self.logger.info("Flow actions: switchMPLS Ingress=%s, out_port=%s", self.label, out_port)
        # Check if the packet is an MPLS packet.
        elif eth.ethertype == ether.ETH_TYPE_MPLS:
            # Get the MPLS label from the packet.
            mpls_pkt = pkt.get_protocols(mpls.mpls)[0]
            mpls_label = mpls_pkt.label

            # Prepare the new MPLS label to be pushed onto the packet.
            self.label = self.label + 1
            # Create the MPLS header with the new label.

            # Update the Ethernet header.
            eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
            eth_pkt.ethertype = ether.ETH_TYPE_MPLS

            # Prepare the actions to push the new MPLS label.
            actions = [parser.OFPActionPopMpls(), parser.OFPActionPushMpls(), 
                     parser.OFPActionSetField(mpls_label=self.label), 
                     parser.OFPActionOutput(out_port)]
            self.logger.info("Flow actions: switchMPLS LSR=%s, out_port=%s", self.label, out_port)
            # Send the actions to the switch to push the new MPLS label.
        elif eth.ethertype == ether.ETH_TYPE_MPLS and self.label < self.label + 3:
            # The switch is a LER# Pop that label!
                 actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]
                 self.logger.info("Flow actions: popMPLS, out_port=%s", out_port)
        
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
        else:
                self.add_flow(datapath, 1, match, actions)
        data = None
            
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                           in_port=in_port,actions=actions, data=data)
                datapath.send_msg(out)
