# Initialize a dictionary to store flow information
flow_data = {}

@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def _flow_stats_reply_handler(self, ev):
    body = ev.msg.body
    
    for stat in sorted([flow for flow in body if flow.priority == 1],
                       key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
        datapath_id = ev.msg.datapath.id
        in_port = stat.match['in_port']
        eth_dst = stat.match['eth_dst']
        
        # Get the byte count and current time
        byte_count = stat.byte_count
        current_time = time.time()
        
        # Create a unique key for each flow
        flow_key = (datapath_id, in_port, eth_dst)
        
        # Check if the flow key exists in the dictionary
        if flow_key in flow_data:
            prev_byte_count, prev_time = flow_data[flow_key]
            
            # Calculate the time difference
            time_diff = current_time - prev_time
            
            # Calculate the byte difference
            byte_diff = byte_count - prev_byte_count
            
            # Calculate the flow speed (bytes per second)
            flow_speed = byte_diff / time_diff
            
            # Print or process the flow speed as desired
            print(f"Flow Speed for {flow_key}: {flow_speed} bytes/s")
        
        # Update the flow data in the dictionary
        flow_data[flow_key] = (byte_count, current_time)
