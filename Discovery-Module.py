# Import the required modules
from itertools import permutations

@set_ev_cls(event.EventSwitchEnter)
def get_topology_data(self, ev):
    # Your existing code to get links and switches data

    # Determine all possible paths between switches
    switch_combinations = permutations(self.switches, 2)
    paths = []
    for src_dpid, dst_dpid in switch_combinations:
        try:
            # Use NetworkX library to find the shortest path
            path = nx.shortest_path(self.topology, src_dpid, dst_dpid)
            paths.append(path)
        except nx.NetworkXNoPath:
            # No path exists between the switches
            pass

    # Calculate bandwidth for each path
    path_bandwidths = {}
    for path in paths:
        path_bandwidth = self.calculate_path_bandwidth(path)
        path_bandwidths[tuple(path)] = path_bandwidth

    # Store the path bandwidths in the class variable
    self.path_bandwidths = path_bandwidths


# Import the required modules
from itertools import permutations

@set_ev_cls(event.EventSwitchEnter)
def get_topology_data(self, ev):
    # Your existing code to get links and switches data

    # Determine all possible paths between switches
    switch_combinations = permutations(self.switches, 2)
    paths = []
    for src_dpid, dst_dpid in switch_combinations:
        try:
            # Use NetworkX library to find the shortest path
            path = nx.shortest_path(self.topology, src_dpid, dst_dpid)
            paths.append(path)
        except nx.NetworkXNoPath:
            # No path exists between the switches
            pass

    # Store each path separately
    self.paths = paths

    # Calculate bandwidth for each path
    path_bandwidths = {}
    for path in paths:
        path_bandwidth = self.calculate_path_bandwidth(path)
        path_bandwidths[tuple(path)] = path_bandwidth

    # Store the path bandwidths in the class variable
    self.path_bandwidths = path_bandwidths



#----------------------------------------------------Updated one------------------------------------------------------------------------------------

# Import the required modules
from itertools import permutations

@set_ev_cls(event.EventSwitchEnter)
def get_topology_data(self, ev):
    # Your existing code to get links and switches data

    # Determine all possible paths between switches
    switch_combinations = permutations(self.switches, 2)
    paths = []
    path_id = 1  # Start with path ID 1
    for src_dpid, dst_dpid in switch_combinations:
        try:
            # Use NetworkX library to find the shortest path
            path = nx.shortest_path(self.topology, src_dpid, dst_dpid)
            paths.append((path_id, path))  # Store path along with its ID
            path_id += 1  # Increment path ID
        except nx.NetworkXNoPath:
            # No path exists between the switches
            pass

    # Store each path separately along with its ID
    self.paths = paths

    # Calculate bandwidth for each path
    path_bandwidths = {}
    for path_id, path in paths:
        path_bandwidth = self.calculate_path_bandwidth(path)
        path_bandwidths[path_id] = path_bandwidth

    # Store the path bandwidths in the class variable
    self.path_bandwidths = path_bandwidths
# bandwidth calculation
def calculate_path_bandwidth(self, path):
    total_bandwidth = float ('inf')  # Initialize with infinite bandwidth

    for i in range(len(path) - 1):
        src_dpid = path[i]
        dst_dpid = path[i + 1]

        # Get the link between src_dpid and dst_dpid
        link = next((link for link in self.links if link[0] == src_dpid and link[1] == dst_dpid), None)

        if link is not None:
            # Retrieve the bandwidth information of the link
            link_bandwidth = self.port_bandwidth[(src_dpid, link[2]['port'])]

            # Update the total bandwidth based on the link bandwidth
            total_bandwidth = min(total_bandwidth, link_bandwidth)

    return total_bandwidth
