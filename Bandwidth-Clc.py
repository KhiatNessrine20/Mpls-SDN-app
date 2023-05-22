import networkx as nx

# Create an empty graph
G = nx.Graph()

# Add switches as nodes to the graph
G.add_nodes_from([1, 2, 3, 4])

# Add links between switches with available bandwidth as edge attribute
G.add_edge(1, 2, bandwidth=100)
G.add_edge(2, 3, bandwidth=50)
G.add_edge(3, 4, bandwidth=80)

#Bandwidths
# Separate and access individual paths
    path_1 = paths[0]
    path_2 = paths[1]

    # Print the individual paths
    print("Path 1:", path_1)
    print("Path 2:", path_2)

    # Calculate bandwidth for each path
    path_bandwidths = {}
    path_bandwidth_1 = self.calculate_path_bandwidth(path_1)
    path_bandwidth_2 = self.calculate_path_bandwidth(path_2)
    path_bandwidths[tuple(path_1)] = path_bandwidth_1
    path_bandwidths[tuple(path_2)] = path_bandwidth_2

    # Store the path bandwidths in the class variable
    self.path_bandwidths = path_bandwidths



#/////
# Measure bandwidth using iperf
            cmd = f"iperf -c {dst} -b {total_bandwidth}M"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            # Parse the output to get the measured bandwidth
            output_lines = result.stdout.split('\n')
            measured_bandwidth = float(output_lines[-2].split()[-2])  # Assuming the output format is consistent

            if measured_bandwidth >= total_bandwidth:





import networkx as nx

# Create an empty graph
G = nx.Graph()

# Add switches as nodes to the graph
G.add_nodes_from([1, 2, 3, 4])

# Add links between switches with available bandwidth as edge attribute
G.add_edge(1, 2, bandwidth=100)
G.add_edge(2, 3, bandwidth=50)
G.add_edge(3, 4, bandwidth=80)

# Example paths
paths = [[1, 2, 3, 4], [1, 3, 4]]

# Iterate over each path
for path in paths:
    # Calculate total available bandwidth on the path
    total_bandwidth = min(G[u][v]['bandwidth'] for u, v in zip(path[:-1], path[1:]))

    # Perform load balancing
    for i in range(len(path) - 1):
        src = path[i]
        dst = path[i + 1]

        # Check if the link exists in the graph
        if G.has_edge(src, dst):
            bandwidth = G[src][dst]['bandwidth']

            if bandwidth >= total_bandwidth:
                # Sufficient bandwidth available on the link
                print(f"Link ({src} - {dst}) has sufficient bandwidth for load balancing.")
            else:
                # Not enough bandwidth on the link
                print(f"Link ({src} - {dst}) does not have enough bandwidth for load balancing.")
        else:
            # Link does not exist in the graph
            print(f"Link ({src} - {dst}) is invalid.")
