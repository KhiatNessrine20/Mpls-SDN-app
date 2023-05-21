
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
        self.port_speed = {}    # record the port speed 
        self.flow_speed = {}    # record the flow speed
        self.sleep = 2          # the interval of getting statistic
        self.state_len = 3      # the length of speed list of per port and flow.

        self.port_bandwidth = {}



    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
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
    
  

    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath       '
                        'in-port eth-dst       '
                        'out-port packets bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)
    
    
    def calculate_link_bandwidth(link):
        total_bandwidth = 0

        for port in link:
            port_bandwidth = self.port_bandwidth.get(port, 0)
            total_bandwidth += port_bandwidth

        return total_bandwidth

    
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath port '
                         'rx-pkts rx-bytes rx-error '
                         'tx-pkts tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (ev.msg.datapath.id, stat.port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, self.state_len)
              # Get port speed.
                pre = 0
                period = self.sleep
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(
                        tmp[-1][3], tmp[-1][4],
                        tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0]+self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, self.state_len)
                print ('\n Speed:\n', self.port_speed)

                 #Calculate bandwidth
                tx_bytes = self.port_stats[key][-1][0]
                duration_sec = self.port_stats[key][-1][3]
                duration_nsec = self.port_stats[key][-1][4]

                measurement_duration = duration_sec + duration_nsec * 1e-9  # Convert to seconds
                bandwidth = (tx_bytes * 8) / measurement_duration  # Calculate bandwidth in bits per second

                self._save_stats(self.port_bandwidth, key, bandwidth, self.state_len)

        link = ['s1', 's2', 's3']  # Example link consisting of switches s1, s2, and s3
        aggregate_bandwidth = self.calculate_link_bandwidth(link)
        print("Aggregate Bandwidth:", aggregate_bandwidth)



        
