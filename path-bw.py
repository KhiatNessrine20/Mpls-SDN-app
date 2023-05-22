import networkx as nx
        
def __init__():
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {}
        self.port_features = {}
        self.free_bandwidth = {}
# Original dictionary representing the graph
#Graph creation
def build_graph():
    graph = {
        'S1': {
        'S2': {'bandwidth': 1000},
        'S3': {'bandwidth': 1000}
    },
    'S2': {
        'S1': {'bandwidth': 1000},
        'S4': {'bandwidth': 1000}
    },
    'S3': {
        'S1': {'bandwidth': 1000},
        'S4': {'bandwidth': 1000}
    },
    'S4': {
        'S3': {'bandwidth': 1000},
        'S2': {'bandwidth': 1000}
    }}

    # Creating an empty networkx graph
    G = nx.DiGraph()

    # Adding nodes to the graph
    for node in graph:
        G.add_node(node)

    # Adding edges and attributes to the graph
    for source, neighbors in graph.items():
        for target, attributes in neighbors.items():
            if 'bandwidth' in attributes:
                bw = attributes['bandwidth']
                G.add_edge(source, target, bandwidth=bw)
    return G


my_graph = build_graph()





def get_min_bw_of_links(self, graph, path):
        """
            Getting bandwidth of path. Actually, the mininum bandwidth
            of links is the bandwith, because it is the neck bottle of path.
        """
        min_bw = float('inf')  # Initialize with a high value
        for i in range(len(path) - 1):
            src, dst = path[i], path[i+1]
            if src in graph and dst in graph[src]:
                if 'bandwidth' in graph[src][dst]:
                    bw = graph[src][dst]['bandwidth']
                    min_bw = min(bw, min_bw)
        return min_bw

min_bw= get_min_bw_of_links(my_graph, path)

def get_path_min_bw(graph, path):
    """
    Calculate the minimum bandwidth of the path between 'S1' and 'S4'.
    """
    path_min_bw = float('inf')

    src, dst = 'S1', 'S4'

    if src in path and dst in path:
        src_index = path.index(src)
        dst_index = path.index(dst)

        if dst_index > src_index + 1:
            for i in range(src_index, dst_index):
                node1, node2 = path[i], path[i + 1]
                if 'bandwidth' in graph[node1][node2]:
                    bw = graph[node1][node2]['bandwidth']
                    path_min_bw = min(bw, path_min_bw)

    return path_min_bw

path_bw= get_path_min_bw(my_graph, path)








def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        return max(capacity / 10**3 - speed * 8, 0)

def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("Fail in getting port state")

def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0



@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('in_port'),
                                             flow.match.get('ipv4_dst'))):
            key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = setting.MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)
        return speed


@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
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
                period = setting.MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)



