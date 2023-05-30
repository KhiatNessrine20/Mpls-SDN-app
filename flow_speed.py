import time
from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub



class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        # Initialize variables
        

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        return max(capacity / 10**3 - speed * 8, 0)
    
    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        #port_feature = (config, state, p.curr_speed)
        #self.port_features[dpid][p.port_no] = port_feature

        #port_no = msg.desc.port_no
        
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
            print("Current bw is:", curr_bw)
            print("Capqcity is:", capacity)
            print("Speed used:", speed)
        else:
            self.logger.info("Fail in getting port state")
        

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)
    
    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0




    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath in-port eth-dst out-port packets bytes')
        self.logger.info('---------------- -------- ----------------- -------- -------- --------')
    
        current_time = time.time()  # Current time
    
        for stat in sorted([flow for flow in body if flow.priority == 1],
                       key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            datapath_id = ev.msg.datapath.id
            in_port = stat.match['in_port']
            eth_dst = stat.match['eth_dst']
            out_port = stat.instructions[0].actions[0].port
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            prev_byte_count = {}
            prev_time = {}
            if (datapath_id, in_port, eth_dst) in prev_byte_count:
                prev_byte = prev_byte_count[(datapath_id, in_port, eth_dst)]
                prev_t = prev_time[(datapath_id, in_port, eth_dst)]
            
                # Calculate time difference
                time_diff = current_time - prev_t
            
                # Calculate byte difference
                byte_diff = byte_count - prev_byte
            
                # Calculate speed (bytes per second)
                speed = byte_diff / time_diff
                speed_kbs = speed*8 / 1000
                MAX_BANDWIDTH = 10000 #(kb/s)
                available_bandwidth = MAX_BANDWIDTH - speed_kbs
            
                self.logger.info('%016x %8x %17s %8x %8d %8d %f',
                             datapath_id, in_port, eth_dst, out_port,
                             packet_count, byte_count, speed)
        
                # Update previous byte count and time
            prev_byte_count[(datapath_id, in_port, eth_dst)] = byte_count
            prev_time[(datapath_id, in_port, eth_dst)] = current_time

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Save port's stats info
        Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        if 'port' not in self.stats:
            self.stats['port'] = {}

        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                     stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = 10
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                          tmp[-2][3], tmp[-2][4])

                    speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],pre, period)

                    self._save_stats(self.port_speed, key, speed, 5)
                    self._save_freebandwidth(dpid, port_no, speed)
                    print("Port Speed:", speed)

