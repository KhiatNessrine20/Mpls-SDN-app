# A ajouter apres l'importation au tout début:
MPLS = mpls.mpls.__name__
# MPLSmod: mpls REST parameters
REST_NetworkAdd = 'NetworkAdd'
REST_PORT = 'port'
REST_ROUTER = 'router'
# MPLSmod: mpls priority values
PRIORITY_MPLS_PREFIX = 1
PRIORITY_PUSH_MPLS = 2
PRIORITY_POP_MPLS = 2
PRIORITY_SWAP_MPLS = 2
# MPLSmod: Tags for actions
MPLS_PUSH_LABEL = 1
MPLS_POP_LABEL = 2
MPLS_SWAP_LABEL = 3
# MPLSmod: Router types
ROUTER_TYPE_LER1 = 'LERIn'
ROUTER_TYPE_LER2 = 'LEREg'
ROUTER_TYPE_LSR = 'LSR'
# MPLSmod: Hardcoded LSR Datapath ID
LSR_DPID1 = '0000000000000002'
LSR_DPID2 = '0000000000000003'
LER_DPID1 = '0000000000000001'
LER_DPID2 = '0000000000000004'

#to add in class Rest router APi
# MPLSmod: Object to allow all routers access mpls data
self.mpls_data = MplsData()
@set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
def datapath_handler(self, ev):
    if ev.enter:
    # MPLSmod: added mpls_data parameter
        RouterController.register_router(ev.dp, self.mpls_data)
    else:
        RouterController.unregister_router(ev.dp)


# Class router Contrller
# MPLSmod: adding mpls_data parameter
@classmethod
def register_router(cls, dp, mpls_data):
    dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
    try:
        router = Router(dp, cls._LOGGER, mpls_data)
    except OFPUnknownVersion as message:
        cls._LOGGER.error(str(message), extra=dpid)
        return
    cls._ROUTER_LIST.setdefault(dp.id, router)
    cls._LOGGER.info('Join as router.', extra=dpid)

# Class router ( f init)
# MPLSmod: object to store all MPLS data (Modified constructor)
self.mpls_data = mpls_data
ofctl = OfCtl.factory(dp, logger)
cookie = COOKIE_DEFAULT_ID


class VlanRouter(object):
    def __init__(self, vlan_id, dp, port_data, logger):
        super(VlanRouter, self).__init__()
        self.vlan_id = vlan_id
        self.dp = dp
        self.sw_id = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        self.logger = logger

        self.port_data = port_data
        self.address_data = AddressData()
        self.routing_tbl = RoutingTable()
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self.ofctl = OfCtl.factory(dp, logger)

        # Set flow: default route (drop)
        self._set_defaultroute_drop()
        #mpls mod
        self.prefix_data = PrefixData()
        self.mpls_label = MplsLabel()
        self.mpls_data = mpls_data
        self.dpid = dpid_lib.dpid_to_str(dp.id)
        self.mpls_data.setdefault(self.dpid, {})
        # MPLSmod: Router type. LER by default
        self.router_type = ROUTER_TYPE_LER
        # Set flow: MPLS packets are sent to the controller
        self.ofctl.set_packetin_flow(0x24, PRIORITY_MPLS_PREFIX,
        dl_type=ether.ETH_TYPE_MPLS)

    def delete(self, waiters):
        # Delete flow.
        msgs = self.ofctl.get_all_flow(waiters)
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id == self.vlan_id:
                    self.ofctl.delete_flow(stats)

        assert len(self.packet_buffer) == 0

    @staticmethod
    def _cookie_to_id(id_type, cookie):
        if id_type == REST_VLANID:
            rest_id = cookie >> COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            rest_id = cookie & UINT32_MAX
        else:
            assert id_type == REST_ROUTEID
            rest_id = (cookie & UINT32_MAX) >> COOKIE_SHIFT_ROUTEID

        return rest_id

    def _id_to_cookie(self, id_type, rest_id):
        vid = self.vlan_id << COOKIE_SHIFT_VLANID

        if id_type == REST_VLANID:
            cookie = rest_id << COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            cookie = vid + rest_id
        else:
            assert id_type == REST_ROUTEID
            cookie = vid + (rest_id << COOKIE_SHIFT_ROUTEID)

        return cookie

    def _get_priority(self, priority_type, route=None):
        return get_priority(priority_type, vid=self.vlan_id, route=route)

    def _response(self, msg):
        if msg and self.vlan_id:
            msg.setdefault(REST_VLANID, self.vlan_id)
        return msg

    def get_data(self):
        address_data = self._get_address_data()
        routing_data = self._get_routing_data()
        # MPLSmod: Port data for the MPLS network
        #prefix_data = self._get_prefix_data()
        data = {}
        if address_data[REST_ADDRESS]:
            data.update(address_data)
        if routing_data[REST_ROUTE]:
            data.update(routing_data)
        #data = {}
        #if address_data[REST_ADDRESS]:
         #   data.update(address_data)
      #  if routing_data[REST_ROUTE]:
          #  data.update(routing_data)

        return self._response(data)

    def _get_address_data(self):
        address_data = []
        for value in self.address_data.values():
            default_gw = ip_addr_ntoa(value.default_gw)
            address = '%s/%d' % (default_gw, value.netmask)
            data = {REST_ADDRESSID: value.address_id,
                    REST_ADDRESS: address}
            address_data.append(data)
        return {REST_ADDRESS: address_data}

    def _get_routing_data(self):
        routing_data = []
        for key, value in self.routing_tbl.items():
            if value.gateway_mac is not None:
                gateway = ip_addr_ntoa(value.gateway_ip)
                data = {REST_ROUTEID: value.route_id,
                        REST_DESTINATION: key,
                        REST_GATEWAY: gateway}
                routing_data.append(data)
        return {REST_ROUTE: routing_data}

    def set_data(self, data):
        details = None

        try:
            # Set address data
            if REST_ADDRESS in data:
                address = data[REST_ADDRESS]
                address_id = self._set_address_data(address)
                details = 'Add address [address_id=%d]' % address_id
            # Set routing data
            elif REST_GATEWAY in data:
                gateway = data[REST_GATEWAY]
                if REST_DESTINATION in data:
                    destination = data[REST_DESTINATION]
                else:
                    destination = DEFAULT_ROUTE
                route_id = self._set_routing_data(destination, gateway)
                details = 'Add route [route_id=%d]' % route_id
            # MPLSmod: set prefix-port mapping data
            elif REST_PREFIX in data:
                prefix = data[REST_PREFIX]
                port = data[REST_PORT]
                prefix_id = self._set_prefix_data(prefix, port)
                details = 'Add prefix to port [prefix_id=%d]' % prefix_id
                    # MPLSmod: set router type
            elif REST_ROUTER in data:
                router = data[REST_ROUTER]
                self._set_router_type(router)
                details = 'Add router type: %s' % router


        except CommandFailure as err_msg:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: str(err_msg)}
            return self._response(msg)

        if details is not None:
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
            return self._response(msg)
        else:
            raise ValueError('Invalid parameter.')
    #Mpls impl
    def _set_router_type(self, router):
        self.router_type = router
        # MPLSmod: set port data method
    def _set_prefix_data(self, prefix, port):
        cookie = 0x800
        prefix = self.prefix_data.add(prefix, port)
        # Set flow: IP packets aiming this prefix are sent to the controller
        priority = self._get_priority(PRIORITY_MPLS_PREFIX)
        self.ofctl.set_packetin_flow(cookie, priority,
        dl_type=ether.ETH_TYPE_IP,
        dst_ip=prefix.address,
        dst_mask=prefix.netmask)
        return prefix.prefix_id
        

    def _set_address_data(self, address):
        address = self.address_data.add(address)

        cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)

        # Set flow: host MAC learning (packet in)
        priority = self._get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=address.nw_addr,
                                     dst_mask=address.netmask)
        log_msg = 'Set host MAC learning (packet in) flow [cookie=0x%x]'
        self.logger.info(log_msg, cookie, extra=self.sw_id)

        # set Flow: IP handling(PacketIn)
        priority = self._get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=address.default_gw)
        self.logger.info('Set IP handling (packet in) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)

        # Set flow: L2 switching (normal)
        outport = self.ofctl.dp.ofproto.OFPP_NORMAL
        priority = self._get_priority(PRIORITY_L2_SWITCHING)
        self.ofctl.set_routing_flow(
            cookie, priority, outport, dl_vlan=self.vlan_id,
            nw_src=address.nw_addr, src_mask=address.netmask,
            nw_dst=address.nw_addr, dst_mask=address.netmask)
        self.logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)

        # Send GARP
        self.send_arp_request(address.default_gw, address.default_gw)

        return address.address_id

    def _set_routing_data(self, destination, gateway):
        err_msg = 'Invalid [%s] value.' % REST_GATEWAY
        dst_ip = ip_addr_aton(gateway, err_msg=err_msg)
        address = self.address_data.get_data(ip=dst_ip)
        if address is None:
            msg = 'Gateway=%s\'s address is not registered.' % gateway
            raise CommandFailure(msg=msg)
        elif dst_ip == address.default_gw:
            msg = 'Gateway=%s is used as default gateway of address_id=%d'\
                % (gateway, address.address_id)
            raise CommandFailure(msg=msg)
        else:
            src_ip = address.default_gw
            route = self.routing_tbl.add(destination, gateway)
            self._set_route_packetin(route)
            self.send_arp_request(src_ip, dst_ip)
            return route.route_id

    def _set_defaultroute_drop(self):
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
        priority = self._get_priority(PRIORITY_DEFAULT_ROUTING)
        outport = None  # for drop
        self.ofctl.set_routing_flow(cookie, priority, outport,
                                    dl_vlan=self.vlan_id)
        self.logger.info('Set default route (drop) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)

    def _set_route_packetin(self, route):
        cookie = self._id_to_cookie(REST_ROUTEID, route.route_id)
        priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                               route=route)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=route.dst_ip,
                                     dst_mask=route.netmask)
        self.logger.info('Set %s (packet in) flow [cookie=0x%x]', log_msg,
                         cookie, extra=self.sw_id)

    def delete_data(self, data, waiters):
        if REST_ROUTEID in data:
            route_id = data[REST_ROUTEID]
            msg = self._delete_routing_data(route_id, waiters)
        elif REST_ADDRESSID in data:
            address_id = data[REST_ADDRESSID]
            msg = self._delete_address_data(address_id, waiters)
        else:
            raise ValueError('Invalid parameter.')

        return self._response(msg)

    def _delete_address_data(self, address_id, waiters):
        if address_id != REST_ALL:
            try:
                address_id = int(address_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ADDRESSID, e.message))

        skip_ids = self._chk_addr_relation_route(address_id)

        # Get all flow.
        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters)
        max_id = UINT16_MAX
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                addr_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                   stats.cookie)
                if addr_id in skip_ids:
                    continue
                elif address_id == REST_ALL:
                    if addr_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
                        continue
                elif address_id != addr_id:
                    continue
                delete_list.append(stats)

        delete_ids = []
        for flow_stats in delete_list:
            # Delete flow
            self.ofctl.delete_flow(flow_stats)
            address_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                  flow_stats.cookie)

            del_address = self.address_data.get_data(addr_id=address_id)
            if del_address is not None:
                # Clean up suspend packet threads.
                self.packet_buffer.delete(del_addr=del_address)

                # Delete data.
                self.address_data.delete(address_id)
                if address_id not in delete_ids:
                    delete_ids.append(address_id)

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(addr_id) for addr_id in delete_ids)
            details = 'Delete address [address_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        if skip_ids:
            skip_ids = ','.join(str(addr_id) for addr_id in skip_ids)
            details = 'Skip delete (related route exist) [address_id=%s]'\
                % skip_ids
            if msg:
                msg[REST_DETAILS] += ', %s' % details
            else:
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}

        return msg

    def _delete_routing_data(self, route_id, waiters):
        if route_id != REST_ALL:
            try:
                route_id = int(route_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ROUTEID, e.message))

        # Get all flow.
        msgs = self.ofctl.get_all_flow(waiters)

        delete_list = []
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                rt_id = VlanRouter._cookie_to_id(REST_ROUTEID, stats.cookie)
                if route_id == REST_ALL:
                    if rt_id == COOKIE_DEFAULT_ID:
                        continue
                elif route_id != rt_id:
                    continue
                delete_list.append(stats)

        # Delete flow.
        delete_ids = []
        for flow_stats in delete_list:
            self.ofctl.delete_flow(flow_stats)
            route_id = VlanRouter._cookie_to_id(REST_ROUTEID,
                                                flow_stats.cookie)
            self.routing_tbl.delete(route_id)
            if route_id not in delete_ids:
                delete_ids.append(route_id)

            # case: Default route deleted. -> set flow (drop)
            route_type = get_priority_type(flow_stats.priority,
                                           vid=self.vlan_id)
            if route_type == PRIORITY_DEFAULT_ROUTING:
                self._set_defaultroute_drop()

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(route_id) for route_id in delete_ids)
            details = 'Delete route [route_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        return msg

    def _chk_addr_relation_route(self, address_id):
        # Check exist of related routing data.
        relate_list = []
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(ip=gateway)
            if address is not None:
                if (address_id == REST_ALL
                        and address.address_id not in relate_list):
                    relate_list.append(address.address_id)
                elif address.address_id == address_id:
                    relate_list = [address_id]
                    break
        return relate_list

    def packet_in_handler(self, msg, header_list):
        # Check invalid TTL (for OpenFlow V1.2/1.3)
        ofproto = self.dp.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION or \
                ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            if msg.reason == ofproto.OFPR_INVALID_TTL:
                self._packetin_invalid_ttl(msg, header_list)
                return

        # Analyze event type.
        if ARP in header_list:
            self._packetin_arp(msg, header_list)
            return
        
        # MPLSmod: If packetin is an MPLS packet
        if MPLS in header_list:
            if self.router_type == ROUTER_TYPE_LER1:
              # LER method (push/pop) a modifié accordingly
            
                self.logger.info('Packet Reached LERIngress: Push Action', extra=self.sw_id)
                self.push_mpls(msg, header_list)
            elif self.router_type == ROUTER_TYPE_LER2:
                self.logger.info('Packet Reached LERRgress: Pop Action', extra=self.sw_id)
                self.pop_mpls(msg, header_list)
            elif self.router_type == ROUTER_TYPE_LSR:
            # LSR method(swap)
                self.logger.info('Packet Reached LSR: Swap Action', extra=self.sw_id)
                self.Swap_mpls(msg, header_list)

        if IPV4 in header_list:
            rt_ports = self.address_data.get_default_gw()
            if header_list[IPV4].dst in rt_ports:
                # Packet to router's port.
                if ICMP in header_list:
                    if header_list[ICMP].type == icmp.ICMP_ECHO_REQUEST:
                        self._packetin_icmp_req(msg, header_list)
                        return
                elif TCP in header_list or UDP in header_list:
                    self._packetin_tcp_udp(msg, header_list)
                    return
            else:
                # Packet to internal host or gateway router.
                #self._packetin_to_node(msg, header_list)
                #mPLS
                self._packetin_to_mpls_network(msg, header_list)

                return
    def push_mpls(self, msg, header_list):
        self.logger.info('MPLS Action: Push Labels',extra=self.sw_id)
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self.logger.info('Packet is dropped, MAX_SUSPENDPACKETS exceeded.',
                extra=self.sw_id)
            return
        in_port = self.ofctl.get_packetin_inport(msg)
        dst_ip = header_list[IPV4].dst
        src_ip = header_list[IPV4].src
        for key in self.prefix_data:
            prefix = self.prefix_data[key]
            if prefix.compare(dst_ip):
              # Write flow & packet out
                priority = self._get_priority(PRIORITY_PUSH_MPLS)
                cookie = 0x810
                out_port = int(prefix.port)
                self.ofctl.set_mpls_flow(cookie, priority, self.mpls_label.value,
                  in_port, out_port, MPLS_PUSH_LABEL, nw_dst=dst_ip,nw_src=src_ip)
                self.ofctl.send_mpls_packet_out(in_port,
                out_port, msg.data, self.mpls_label.value, MPLS_PUSH_LABEL)
                self.mpls_data.add(self.dpid, self.mpls_label.value, dst_ip)
                self.mpls_label.increase()
                break
    
    # MPLSmod: When packet enters LSR
    def Swap_mpls(self, msg, header_list):
        in_port = self.ofctl.get_packetin_inport(msg)
        dst_ip = header_list[IPV4].dst
        src_ip = header_list[IPV4].src
        label_in = self.ofctl.get_packetin_mplslabel(msg)
        self.logger.info('Recieved Label: %s' % label_in,extra=self.sw_id)
        address = 0
        orig_id = self.get_origin_id_lsr(in_port)
        self.logger.info('Origin ID (sent by): %s' % orig_id,extra=self.sw_id)
        for label in self.mpls_data[orig_id]:
            self.logger.info('Labels pushed by origin: %s' % str(label),extra=self.sw_id)
            if label == label_in:
               self.logger.info('Label match: %s' % str(label),extra=self.sw_id)
               address = self.mpls_data[orig_id][label]
               break
        for key in self.prefix_data:
            prefix = self.prefix_data[key]
            if address == 0:
                self.logger.info('No label match! Dropping packet...',extra=self.sw_id)
                break
            if prefix.compare(address):
                self.logger.info('Matched! MPLS Action: Swapping label...',extra=self.sw_id)
                     # Create a new label:
                self.mpls_label.increase()
                # Write flow & packet out
                priority = self._get_priority(PRIORITY_SWAP_MPLS)
                cookie = 0x820
                out_port = int(prefix.port)
                self.ofctl.set_mpls_flow(cookie, priority, self.mpls_label.value,
                in_port, out_port, MPLS_SWAP_LABEL, nw_dst=dst_ip,
                nw_src=src_ip, oldlabel=label_in)
                self.ofctl.send_mpls_packet_out(in_port,
                out_port, msg.data, self.mpls_label.value, MPLS_SWAP_LABEL)
                self.mpls_data.add(self.dpid, self.mpls_label, dst_ip)
                break

    def pop_mpls(self, msg, header_list):
            # Extract data
        in_port = self.ofctl.get_packetin_inport(msg)
        dst_ip = header_list[IPV4].dst
        src_ip = header_list[IPV4].src
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(dst_ip)
        label_in = self.ofctl.get_packetin_mplslabel(msg)
        if dst_ip not in self.hosts:
           # Send ARP to learn the MAC address
            address = self.address_data.get_data(ip=dst_ip)
            if address is not None:
                log_msg = 'Receive IP packet from [%s] to an internal host [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                src_ip = address.default_gw
            if src_ip is not None:
                self.packet_buffer.add(in_port, header_list, msg.data)
                self.send_arp_request(src_ip, dst_ip, in_port=in_port)
                self.logger.info('Send ARP request (flood)', extra=self.sw_id)
        else:
              # Write flow & packet out
            priority = self._get_priority(PRIORITY_POP_MPLS)
            cookie = 0x830
            out_port = self.hosts[dst_ip].por
            dl_src = self.port_data[out_port].mac
            dl_dst = self.hosts[dst_ip].mac
            self.ofctl.set_mpls_flow(cookie, priority, self.mpls_label.value,
            in_port, out_port, MPLS_POP_LABEL, nw_dst=dst_ip,
            dst_mac=dl_dst, src_mac=dl_src, oldlabel=label_in)
            self.ofctl.send_mpls_packet_out(in_port, out_port, msg.data,
            self.mpls_label.value, MPLS_POP_LABEL, dst_mac=dl_dst,src_mac=dl_src)
            # MPLSmod: Get origin LSR ID, quick and dirty method
    def get_lsr_id(self, ler_id):
        if ler_id is not None:
            return LSR_DPID
              #    MPLSmod: Get origin ID, quick and dirty method
    def get_origin_id_lsr(self, in_port):
        return "000000000000000" + str(in_port)



    def _packetin_arp(self, msg, header_list):
        src_addr = self.address_data.get_data(ip=header_list[ARP].src_ip)
        if src_addr is None:
            return

        # case: Receive ARP from the gateway
        #  Update routing table.
        # case: Receive ARP from an internal host
        #  Learning host MAC.
        gw_flg = self._update_routing_tbl(msg, header_list)
        if gw_flg is False:
            self._learning_host_mac(msg, header_list)

        # ARP packet handling.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip
        srcip = ip_addr_ntoa(src_ip)
        dstip = ip_addr_ntoa(dst_ip)
        rt_ports = self.address_data.get_default_gw()

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
            self.ofctl.send_packet_out(in_port, output, msg.data)

            self.logger.info('Receive GARP from [%s].', srcip,
                             extra=self.sw_id)
            self.logger.info('Send GARP (normal).', extra=self.sw_id)

        elif dst_ip not in rt_ports:
            dst_addr = self.address_data.get_data(ip=dst_ip)
            if (dst_addr is not None and
                    src_addr.address_id == dst_addr.address_id):
                # ARP from internal host -> packet forward (normal)
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)

                self.logger.info('Receive ARP from an internal host [%s].',
                                 srcip, extra=self.sw_id)
                self.logger.info('Send ARP (normal)', extra=self.sw_id)
        else:
            if header_list[ARP].opcode == arp.ARP_REQUEST:
                # ARP request to router port -> send ARP reply
                src_mac = self.port_data[in_port].mac
                dst_mac = header_list[ARP].src_mac
                arp_target_mac = dst_mac
                output = in_port
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    src_mac, dst_mac, dst_ip, src_ip,
                                    arp_target_mac, in_port, output)

                log_msg = 'Receive ARP request from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                self.logger.info('Send ARP reply to [%s]', srcip,
                                 extra=self.sw_id)

            elif header_list[ARP].opcode == arp.ARP_REPLY:
                #  ARP reply to router port -> suspend packets forward
                log_msg = 'Receive ARP reply from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)

                packet_list = self.packet_buffer.get_data(src_ip)
                if packet_list:
                    # stop ARP reply wait thread.
                    for suspend_packet in packet_list:
                        self.packet_buffer.delete(pkt=suspend_packet)

                    # send suspend packet.
                    output = self.ofctl.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)
                        self.logger.info('Send suspend packet to [%s].',
                                         srcip, extra=self.sw_id)

    def _packetin_icmp_req(self, msg, header_list):
        # Send ICMP echo reply.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE,
                             icmp_data=header_list[ICMP].data)

        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(header_list[IPV4].dst)
        log_msg = 'Receive ICMP echo request from [%s] to router port [%s].'
        self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
        self.logger.info('Send ICMP echo reply to [%s].', srcip,
                         extra=self.sw_id)

    def _packetin_tcp_udp(self, msg, header_list):
        # Send ICMP port unreach error.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)

        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(header_list[IPV4].dst)
        self.logger.info('Receive TCP/UDP from [%s] to router port [%s].',
                         srcip, dstip, extra=self.sw_id)
        self.logger.info('Send ICMP destination unreachable to [%s].', srcip,
                         extra=self.sw_id)

    def _packetin_to_node(self, msg, header_list):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self.logger.info('Packet is dropped, MAX_SUSPENDPACKETS exceeded.',
                             extra=self.sw_id)
            return

        # Send ARP request to get node MAC address.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = None
        dst_ip = header_list[IPV4].dst
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(dst_ip)

        address = self.address_data.get_data(ip=dst_ip)
        if address is not None:
            log_msg = 'Receive IP packet from [%s] to an internal host [%s].'
            self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
            src_ip = address.default_gw
        else:
            route = self.routing_tbl.get_data(dst_ip=dst_ip)
            if route is not None:
                log_msg = 'Receive IP packet from [%s] to [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                gw_address = self.address_data.get_data(ip=route.gateway_ip)
                if gw_address is not None:
                    src_ip = gw_address.default_gw
                    dst_ip = route.gateway_ip

        if src_ip is not None:
            self.packet_buffer.add(in_port, header_list, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port)
            self.logger.info('Send ARP request (flood)', extra=self.sw_id)

    def _packetin_invalid_ttl(self, msg, header_list):
        # Send ICMP TTL error.
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        self.logger.info('Receive invalid ttl packet from [%s].', srcip,
                         extra=self.sw_id)

        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                                 icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)
            self.logger.info('Send ICMP time exceeded to [%s].', srcip,
                             extra=self.sw_id)

    def send_arp_all_gw(self):
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(ip=gateway)
            self.send_arp_request(address.default_gw, gateway)

    def send_arp_request(self, src_ip, dst_ip, in_port=None):
        # Send ARP request from all ports.
        for send_port in self.port_data.values():
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, inport, output)

    def send_icmp_unreach_error(self, packet_buffer):
        # Send ICMP host unreach error.
        self.logger.info('ARP reply wait timer was timed out.',
                         extra=self.sw_id)
        src_ip = self._get_send_port_ip(packet_buffer.header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(packet_buffer.in_port,
                                 packet_buffer.header_list,
                                 self.vlan_id,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=packet_buffer.data,
                                 src_ip=src_ip)

            dstip = ip_addr_ntoa(packet_buffer.dst_ip)
            self.logger.info('Send ICMP destination unreachable to [%s].',
                             dstip, extra=self.sw_id)

    def _update_routing_tbl(self, msg, header_list):
        # Set flow: routing to gateway.
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.port_data[out_port].mac
        src_ip = header_list[ARP].src_ip

        gateway_flg = False
        for key, value in self.routing_tbl.items():
            if value.gateway_ip == src_ip:
                gateway_flg = True
                if value.gateway_mac == src_mac:
                    continue
                self.routing_tbl[key].gateway_mac = src_mac

                cookie = self._id_to_cookie(REST_ROUTEID, value.route_id)
                priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                                       route=value)
                self.ofctl.set_routing_flow(cookie, priority, out_port,
                                            dl_vlan=self.vlan_id,
                                            src_mac=dst_mac,
                                            dst_mac=src_mac,
                                            nw_dst=value.dst_ip,
                                            dst_mask=value.netmask,
                                            dec_ttl=True)
                self.logger.info('Set %s flow [cookie=0x%x]', log_msg, cookie,
                                 extra=self.sw_id)
        return gateway_flg

    def _learning_host_mac(self, msg, header_list):
        # Set flow: routing to internal Host.
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.port_data[out_port].mac
        src_ip = header_list[ARP].src_ip
        # MPLSmod: store values
        self.hosts.add(src_ip, out_port, src_mac)
        gateways = self.routing_tbl.get_gateways()
        if src_ip not in gateways:
            address = self.address_data.get_data(ip=src_ip)
            if address is not None:
                cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
                priority = self._get_priority(PRIORITY_IMPLICIT_ROUTING)
                self.ofctl.set_routing_flow(cookie, priority,
                                            out_port, dl_vlan=self.vlan_id,
                                            src_mac=dst_mac, dst_mac=src_mac,
                                            nw_dst=src_ip,
                                            idle_timeout=IDLE_TIMEOUT,
                                            dec_ttl=True)
                self.logger.info('Set implicit routing flow [cookie=0x%x]',
                                 cookie, extra=self.sw_id)

    def _get_send_port_ip(self, header_list):
        try:
            src_mac = header_list[ETHERNET].src
            if IPV4 in header_list:
                src_ip = header_list[IPV4].src
            else:
                src_ip = header_list[ARP].src_ip
        except KeyError:
            self.logger.debug('Receive unsupported packet.', extra=self.sw_id)
            return None

        address = self.address_data.get_data(ip=src_ip)
        if address is not None:
            return address.default_gw
        else:
            route = self.routing_tbl.get_data(gw_mac=src_mac)
            if route is not None:
                address = self.address_data.get_data(ip=route.gateway_ip)
                if address is not None:
                    return address.default_gw

        self.logger.debug('Receive packet from unknown IP[%s].',
                          ip_addr_ntoa(src_ip), extra=self.sw_id)
        return None

    # MPLSmod: classes to store host data
class HostDict(dict):
    def __init__(self):
        super(HostDict, self).__init__()
    def add(self, ip, port, mac):
        self[ip] = Host(ip, port, mac)

class Host(object):
    def __init__(self, ip, port, mac):
        self.ip = ip
        self.port = port
        self.mac = mac

# MPLSmod: class to store the prefix-port info
class PrefixData(dict):
    def __init__(self):
        super(PrefixData, self).__init__()
        self.prefix_id = 1
# Does not check for overlaps yet
    def add(self, prefix, port):
        err_msg = 'invalid [%s] value.' % REST_PREFIX
        nw_addr, mask, default_gw = nw_addr_aton(prefix, err_msg=err_msg)
        prefix = Prefix(nw_addr, mask, port, self.prefix_id)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d'% (ip_str, mask)
        self[key] = prefix
        self.prefix_id = self.prefix_id + 1
        return prefix
# MPLSmod: class to encapsulate the prefix-port relation
class Prefix(object):
    def __init__(self, address, netmask, port, prefix_id):
        self.prefix_id = prefix_id
        self.address = address
        self.netmask = netmask
        self.port = port
    def compare(self, ip):
        if ipv4_apply_mask(ip, self.netmask) == self.address:
            return True
        
        else:
            return False
# MPLSmod: class mapping IP addresses to labels
class MplsData(dict):
    def __init__(self):
        super(MplsData, self).__init__()
    def add(self, dpid, label_value, dst_ip):
        self[dpid][label_value] = dst_ip
       # MPLSmod: class to encapsulate labels
class MplsLabel(object):
    def __init__(self, value=16):
        self.value = value
    def increase(self):
        self.value = self.value + 1
class AddressData(dict):
    def __init__(self):
        super(AddressData, self).__init__()
        self.address_id = 1
    def add(self, address):
        err_msg = 'Invalid [%s] value.' % REST_ADDRESS
        nw_addr, mask, default_gw = nw_addr_aton(address, err_msg=err_msg)
        # Check overlaps
        for other in self.values():
            other_mask = mask_ntob(other.netmask)
            add_mask = mask_ntob(mask, err_msg=err_msg)
        if (other.nw_addr == ipv4_apply_mask(default_gw, other.netmask) or
            nw_addr == ipv4_apply_mask(other.default_gw, mask,err_msg)):
                msg = 'Address overlaps [address_id=%d]' % other.address_id
                raise CommandFailure(msg=msg)
        address = Address(self.address_id, nw_addr, mask, default_gw)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address
        self.address_id += 1
        self.address_id &= UINT32_MAX
        if self.address_id == COOKIE_DEFAULT_ID:
            self.address_id = 1
            return address

# Class ofctl

def send_mpls_packet_out(self, in_port, out_port, data, label, action,dst_mac=0, src_mac=0):
    parser = self.dp.ofproto_parser
    if action == MPLS_PUSH_LABEL:
        actions = [parser.OFPActionPushMpls(ethertype=34887),
          parser.OFPActionSetField(mpls_label=label),
           parser.OFPActionOutput(out_port)]
    elif action == MPLS_SWAP_LABEL:
        actions = [parser.OFPActionPopMpls(),
        parser.OFPActionPushMpls(ethertype=34887),
        parser.OFPActionSetField(mpls_label=label),
        parser.OFPActionOutput(out_port)]
    elif action == MPLS_POP_LABEL:
        actions = [parser.OFPActionPopMpls(),
        parser.OFPActionSetField(eth_src=src_mac),
        parser.OFPActionSetField(eth_dst=dst_mac),
        parser.OFPActionOutput(out_port)]
        self.dp.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
          actions=actions, data=data)
# class ofcrl 1_v13
def set_mpls_flow(self, cookie, priority, label, in_port, out_port, action,dl_vlan=0, nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,src_mac=0, dst_mac=0, idle_timeout=0, oldlabel=0):
    parser = self.dp.ofproto_parser
    if action == MPLS_PUSH_LABEL:
        dl_type = ether.ETH_TYPE_IP
        actions = [parser.OFPActionPushMpls(ethertype=34887),
        parser.OFPActionSetField(mpls_label=label),
        parser.OFPActionOutput(out_port)]
        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,nw_src=nw_src, src_mask=src_mask,nw_dst=nw_dst, dst_mask=dst_mask,idle_timeout=idle_timeout, actions=actions)
    elif action == MPLS_SWAP_LABEL:
        dl_type = ether.ETH_TYPE_MPLS
        actions = [parser.OFPActionPopMpls(),parser.OFPActionPushMpls(ethertype=34887),parser.OFPActionSetField(mpls_label=label),parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port,
        eth_type=dl_type, mpls_label=oldlabel)
        self.set_my_flow(cookie, priority, match,
        idle_timeout=idle_timeout, actions=actions)
    elif action == MPLS_POP_LABEL:
        dl_type = ether.ETH_TYPE_MPLS
        actions = [parser.OFPActionPopMpls(),parser.OFPActionSetField(eth_src=src_mac),parser.OFPActionSetField(eth_dst=dst_mac),parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_type=dl_type, mpls_label=oldlabel)
        self.set_my_flow(cookie, priority, match,
        idle_timeout=idle_timeout, actions=actions)
         # MPLSmod: get mpls label
    def get_packetin_mplslabel(self, msg):
        pkt = packet.Packet(msg.data)
        mpls_proto = pkt.get_protocol(mpls.mpls)
        return mpls_proto.label






