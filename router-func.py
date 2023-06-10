from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, icmp
from ryu.lib.packet import ether_types
from ryu.lib.dpid import dpid_to_str
from ryu.lib import mac as mac_lib
from ryu.utils import hex_array
import ipaddress




class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)

        self.routing_table = {"0000000000000001": {"10.0.1.1/24": {"out_port": 1, "next_hop": None},
                                "10.0.2.0/24": [{"out_port": 2, "next_hop": "192.25.6.1"},
                                                {"out_port": 3, "next_hop": "192.25.6.7"} ]
                                },
                          "0000000000000002": { "10.0.1.0/24": {"out_port": 1, "next_hop": "192.25.6.2"},
                                   "10.0.2.0/24": {"out_port": 2, "next_hop": "192.25.6.9"}
                                },
                          "0000000000000003": {"10.0.1.0/24": {"out_port": 1, "next_hop": "192.25.6.8"},
                                 "10.0.2.0/24": {"out_port": 2, "next_hop": "192.25.6.5"}
                                },
                          "0000000000000004": {"10.0.1.0/24": {"out_port": 1, "next_hop": "192.25.6.10"},
                                 "10.0.2.0/24": [{"out_port": 2, "next_hop": "192.25.6.6"},
                                                 {"out_port": 3, "next_hop": None}]
                                }
                        }

        self.port_table = {"0000000000000001": {"1": {"mac_address": "11:00:00:00:00:12"},
                                  "2": {"mac_address": "11:00:00:00:11:11"},
                                  "3": {"mac_address": "11:00:00:00:11:13"}},
                          "0000000000000002": { "1": {"mac_address": "11:00:00:11:11:11"},
                                  "2": {"mac_address": "11:00:00:11:11:12"}},
                          "0000000000000003": {"1": {"mac_address": "11:00:11:11:11:11"},
                                  "2": {"mac_address": "11:00:11:11:11:12"}},
                           "0000000000000004": { "1": {"mac_address": "11:11:11:11:11:11"},
                                   "2": {"mac_address": "11:11:11:11:11:12"},
                                   "3": {"mac_address": "11:10:00:00:00:12"}}
                         }

        self.arp_table = {"0000000000000001": [{"ip_address": "10.0.1.1/24", "mac_address": "11:00:00:00:00:11"},
                                 {"ip_address": "10.0.1.2/24", "mac_address": "11:00:00:00:00:12"},
                                 {"ip_address": "192.25.6.1/24", "mac_address": "11:00:00:00:11:11"},
                                  {"ip_address": "192.25.6.7/24", "mac_address": "11:00:00:00:11:13"}],
                          "0000000000000002": [{"ip_address": "192.25.6.2/24", "mac_address": "11:00:00:11:11:11"},
                                 {"ip_address": "192.25.6.9/24", "mac_address": "11:00:00:11:11:12"}],
                          "0000000000000003": [{"ip_address": "192.25.6.8/24", "mac_address": "11:00:00:11:11:11"},
                                  {"ip_address": "192.25.6.5/24", "mac_address": "11:00:00:11:11:12"}],
                          "0000000000000004": [{"ip_address": "192.25.6.10/24", "mac_address": "11:00:11:11:11:11"},
                                 {"ip_address": "192.25.6.6/24", "mac_address": "11:00:11:11:11:12"},
                                 {"ip_address": "10.0.2.2/24", "mac_address": "11:10:00:00:00:12"}]
                        }
        self.interface_table = {"0000000000000001": [ {"port": 1, "ip": "10.0.1.2/24"},{"port": 2, "ip": "192.25.6.1/24"}, {"port": 3, "ip": "192.25.6.7/24"}],
                                 "0000000000000002": [ {"port": 1, "ip": "192.25.6.2/24"},{"port": 2, "ip": "192.25.6.9/24"}],
                                 "0000000000000003": [{"port": 1, "ip": "192.25.6.8/24"},{"port": 2, "ip": "192.25.6.5/24"} ],
                                 "0000000000000004": [{"port": 1, "ip": "192.25.6.10/24"},{"port": 2, "ip": "192.25.6.6/24"},{"port": 3, "ip": "10.0.2.2/24"}]
                               }
   
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def find_route(self, dpid, ip_address):
        results = []
        if dpid in self.routing_table:
            routes = self.routing_table[dpid]
            for network, route in routes.items():
                if isinstance(route, dict):
                    out_port = route.get("out_port")
                    next_hop = route.get("next_hop")
                    if next_hop is None:
                      # Handle next_hop is None case
                        results.append({"Network": network, "Out Port": out_port, "Next Hop": "Directly connected"})
                    elif "ip_addresses" in route and ip_address in route["ip_addresses"]:
                        # IP address exists in the route
                        results.append({"Network": network, "Out Port": out_port, "Next Hop": next_hop})
            
                elif isinstance(route, list):
                # Handle multiple routes case
                    for i, entry in enumerate(route, start=1):
                        out_port = entry.get("out_port")
                        next_hop = entry.get("next_hop")
                        if "ip_addresses" in entry and ip_address in entry["ip_addresses"]:
                        # IP address exists in the entry
                            results.append({"Path": i, "Network": network, "Out Port": out_port, "Next Hop": next_hop})
    
        else:
            results.append(f"Switch with dpid {dpid} not found in the routing table.")
    
        return results
     #does it check using switch
    def find_mac_address(self,  ip_address):
        for switch, entries in self.arp_table.items():
            for entry in entries:
                 if entry["ip_address"] == ip_address:
                    return entry["mac_address"]
        return None 

    
    def get_mac_address(self,switch, port):
        if switch in self.port_table and port in self.port_table[switch]:
            return self.port_table[switch][port].get("mac_address")
        return None

    def send_icmp(self, datapath, dst_ip, src_mac, icmp_type, icmp_code, ip_ihl, icmp_data):
        self.logger.info("Sending ICMP")
        proto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_to_str(datapath.id)

        pkt = packet.Packet()

        out_port, hop_ip = self.find_route(dpid, dst_ip)
        out_mac = self.get_mac_address(dpid, out_port)
        dst_mac = src_mac
        #self.logger.debug("Router {} sending ICMP to {} with target MAC {} (from port {} hopping to {})".format(dpid, dst_ip, dst_mac, out_port, hop_ip))
        self.logger.info("Router {} sending ICMP to {} with target MAC {} (from port {} hopping to {})".format(dpid, dst_ip, dst_mac, out_port, hop_ip))

        for interface in self.interface_table.get(dpid):
            if interface.get("port") == out_port:
                src_ip = interface.get("ip")
        
        offset = 14 + 8 + (ip_ihl * 4)
        payload = icmp_data[14:offset]

        if icmp_type == 3:
            self.logger.info("TYPE 3 ICMP: DST Unreachable")
            payload = icmp.dest_unreach(data=payload)
        
        if icmp_type == 11:
            self.logger.info("TYPE 11 ICMP: Time Exceeded")
            payload = icmp.TimeExceeded(data=payload)

        ## pkt.add_protocol(...)
        ## https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_icmp.html

        pkt.add_protocol(ethernet.ethernet(
            dst=dst_mac,
            src=out_mac,
            ethertype=ethernet.ether.ETH_TYPE_IP
        ))
        pkt.add_protocol(ipv4.ipv4(
            dst=dst_ip,
            src=src_ip,
            ttl=64,
            proto=ipv4.inet.IPPROTO_ICMP
        ))
        pkt.add_protocol(icmp.icmp(
            type_=icmp_type,
            code=icmp_code,
            data=payload
        ))

        pkt.serialize()
        data = pkt.data
        actions = [datapath.ofproto_parser.OFPActionOutput(port=out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=proto.OFP_NO_BUFFER, in_port=proto.OFPP_ANY, actions=actions, data=data)
        datapath.send_msg(out)

    
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_pkt_in(self, ev):
        self.logger.info("Packet In")
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        reason = ev.msg.reason
        dpid = dpid_to_str(datapath.id)
        in_port = ev.msg.match['in_port']
        data = ev.msg.data
        pkt = packet.Packet(data)

      # Get packet's Ethernet info
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        mac_dst = pkt_eth.dst
        mac_src = pkt_eth.src
        eth_typ = pkt_eth.ethertype

        if eth_typ == 0x0800:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            ip_dst = pkt_ipv4.dst
            ip_src = pkt_ipv4.src
            ip_ihl = pkt_ipv4.header_length
            ip_ttl = pkt_ipv4.ttl

            if pkt_ipv4.proto == 1:  # ICMP
                self.logger.info("Incoming packet is ICMP")
            if ip_ttl <= 1:
                # Send ICMP time exceeded message
                self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src,
                               icmp_type=11, icmp_code=0, ip_ihl=ip_ihl, icmp_data=data)
                

         # Check packets IP against routing table - including subnets - and get the hop IP and the output port
        routes = self.find_route(dpid, ip_dst)
        if not routes:
            # Destination is not in routing table, send ICMP destination unreachable message
            self.logger.info("Destination is not in routing table")
            self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src,
                           icmp_type=3, icmp_code=0, ip_ihl=ip_ihl, icmp_data=data)
            return

        out_port = routes[0].get("Out Port")
        hop_ip = routes[0].get("Next Hop")
        if hop_ip is None:
            hop_ip = ip_dst

        # Get MAC of next hop from ARP table
        hop_mac = self.find_mac_address( hop_ip)
        if hop_mac is None:
            # Hop IP isn't in ARP table, send ICMP host unreachable message
            self.logger.info("Hop IP {} isn't in ARP table".format(hop_ip))
            self.send_icmp(datapath=datapath, dst_ip=ip_src, src_mac=mac_src,
                           icmp_type=3, icmp_code=1, ip_ihl=ip_ihl, icmp_data=data)
            return

        # Change packet's MAC dst to the next hop, and MAC src to the outgoing port's MAC
        out_mac = self.get_mac_address(dpid, out_port)
        if out_mac is None:
            # Unknown error occurred, return
            return

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=out_mac),
            parser.OFPActionSetField(eth_dst=hop_mac),
            parser.OFPActionOutput(port=out_port)
        ]

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(ip_dst, '255.255.255.0'))
        self.add_flow(datapath, 5, match, actions)

        # Send packet
        self.logger.info("{}: Routing packet (TTL {}) to {} with target MAC {} (from port {} hopping to {})".format(
            dpid, ip_ttl, ip_dst, hop_mac, out_port, hop_ip))
        datapath.send_msg(parser.OFPPacketOut(datapath, ev.msg.buffer_id, in_port, actions, data))

