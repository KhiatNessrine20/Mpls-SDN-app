from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.log import setLogLevel, info

class MPLS_Netwoork(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        LER_Ingress= s1
        LER_Egress =s4

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        # Add links
        self.addLink(s1, s2)
        self.addLink (s1,s3)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s1, h1)
        self.addLink (s1,h2)
        self.addLink(s4, h3)

def start():
    # Create topology
    topo = MPLS_Netwoork()

    # Create network
    net = Mininet(topo=topo, controller=Controller, switch=OVSSwitch)
    print("Creating Network")

    # Start network
    net.start()
    print("Starting...")
    print("Setting Hosts IP addresses...")

    # Set hosts' IP addresses
    h1 = net.get('h1')
    h1.cmd('ifconfig h1-eth0 10.0.0.1 netmask 255.255.255.0')
    h2 = net.get('h2')
    h2.cmd('ifconfig h2-eth0 10.0.0.2 netmask 255.255.255.0')
    h2 = net.get('h3')
    h2.cmd('ifconfig h3-eth0 10.0.0.3 netmask 255.255.255.0')

    # CLI
    net.interact()

    # Stop network
    net.stop()

if __name__ == '__main__':
    # Set log level
    setLogLevel('info')

    # Start topology
    start()
