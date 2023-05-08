from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.net = nx.Graph()
        self.links = {}
        self.switches = {}
        self.switch_ports = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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
    def _packet_in_handler(self, ev):
            # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

       # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = in_port

        #if dst in self.mac_to_port[dpid]:
            #out_port = self.mac_to_port[dpid][dst]
       
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,{'port':msg.in_port})  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,src,dst) # get shortest path  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port'] #get output port
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)# Rest of the code...

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]

        # Store links and switches data in the class variables
        self.links = links
        self.switches = switches

        # Determine input and output ports for each switch
        for src_dpid, dst_dpid, link_info in links:
            if src_dpid not in self.switch_ports:
                self.switch_ports[src_dpid] = {'in_port': [], 'out_port': []}

            if dst_dpid not in self.switch_ports:
                self.switch_ports[dst_dpid] = {'in_port': [], 'out_port': []}

            # Add the input and output ports for each switch
            self.switch_ports[src_dpid]['out_port'].append(link_info['port'])
            self.switch_ports[dst_dpid]['in_port'].append(link_info['port'])

    # Rest of the code...


////
  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
    msg = ev.msg
    datapath = msg.datapath
    parser = datapath.ofproto_parser

    # Get the input switch (datapath) ID
    dpid = format(datapath.id, "d").zfill(16)

    # Check if the input switch ID is in the switch_ports dictionary
    if dpid in self.switch_ports:
        # Get the input port for the current switch
        in_ports = self.switch_ports[dpid]['in_port']

        # Get the output ports for the current switch
        out_ports = self.switch_ports[dpid]['out_port']

        # Rest of the code for handling input/output ports

        # Get the source and destination MAC addresses from the received packet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # Calculate the shortest path using Networkx
        src_switch = 's' + dpid
        dst_switch = 's5'  # Example: Destination switch is s5
        paths = nx.all_shortest_paths(self.net, source=src_switch, target=dst_switch)

        # Assume the first shortest path as the selected path
        selected_path = next(paths)

        # Check if the destination MAC address is known
        if dst_mac in self.mac_to_port[dpid]:
            # Forward the packet to the output port corresponding to the destination MAC address
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            # Forward the packet to all output ports
            out_port = ofproto_v1_3.OFPP_FLOOD

        # Check if the calculated output port is in the output ports list
        if out_port in out_ports:
            actions = [parser.OFPActionOutput(out_port)]

            # Install a flow to avoid packet_in next time
            if out_port != ofproto_v1_3.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_ports[0], eth_dst=dst_mac, eth_src=src_mac)
                if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

            # Send the packet out the specified output port
            data = None
            if msg.buffer_id == ofproto_v1_3.OFP_NO_BUFFER:
                data = msg.data

            # Forward the packet along the selected path
            for i in range(len(selected_path) - 1):
                current_switch = selected_path[i]
                next_switch = selected_path[i + 1]

                # Check if the current switch ID is in the switch_ports dictionary
                if current_switch in self.switch_ports:
                    # Get the output port from the current switch to the next switch
                    if next_switch in self.switch_ports[current_switch]['out_port']:
                        out_port = self.switch_ports[current_switch]['out_port'][next_switch]
                        actions = [parser.OFPActionOutput(out_port)]

                        # Send the packet out the specified output port
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_ports[0], actions=actions, data=data)
                        datap
///////

for i in range(len(path)-1):
            src_node = path[i]
            dst_node = path[i+1]
            in_port = self.get_input_port(src_node)
            out_port = self.get_output_port(dst_node)

   def get_input_port(self, switch, path):
    # Determine the input port for a switch in the path
    if switch == path[0]:
        return path[1]['in_port']  # Input port from the previous switch in the path
    else:
        # Find the link that connects to the previous switch in the path
        for link in self.network_topology[switch]:
            if link['dst'] == path[path.index(switch) - 1]:
                return link['src_port']  # Input port from the link

def get_output_port(self, switch, path):
    # Determine the output port for a switch in the path
    if switch == path[-1]:
        return path[-2]['out_port']  # Output port to the next switch in the path
    else:
        # Find the link that connects to the next switch in the path
        for link in self.network_topology[switch]:
            if link['dst'] == path[path.index(switch) + 1]:
                return link['dst_port']  # Output port to the link
