from mininet.topo import Topo
from mininet.link import TCLink
class MyTopo( Topo ):
  

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        s1 = self.addSwitch ('s1', dpid='0000000000000001')
        s2 = self.addSwitch ('s2',dpid='0000000000000002')
        s3 = self.addSwitch( 's3',dpid='0000000000000003' )
        s4 = self.addSwitch( 's4',dpid='0000000000000004' )
        

        # Add links
        self.addLink( h1, s1 )
        self.addLink( s1, s2 )
        #self.addLink( s2, s3)
        self.addLink( s1, s3 )
        self.addLink( s2, s4)
        self.addLink( s3, s4)
        self.addLink( s4, h2 )
       
       # Adress Assignment
        h1.intf( 'h1-eth0' ).setIP( '10.0.1.1', 24 )
        h1.intf( 'h1-eth0' ).setMAC( '11:00:00:00:00:11' )
        h1.setARP( '10.0.1.2', '11:10:00:00:00:12' )

        h2.intf( 'h2-eth0' ).setIP( '10.0.2.1', 24 )
        h2.intf( 'h2-eth0' ).setMAC( '11:11:11:11:11:11' )
        h2.setARP( '10.0.2.2', '11:10:00:00:00:12:' )

        s1.intf( 's1-eth1' ).setMAC( '11:00:00:00:00:12' )
        s1.intf( 's1-eth1' ).setIP( '10.0.1.2', 24 )
        s1.intf( 's1-eth2' ).setMAC( '11:00:00:00:11:11' )
        s1.intf( 's1-eth2' ).setIP( '192.25.6.1', 24 )
        s1.intf( 's1-eth3' ).setMAC( '11:00:00:00:11:13' )
        s1.intf( 's1-eth3' ).setIP( '192.25.6.7', 24 )
       
        s2.intf( 's2-eth1' ).setMAC( '11:00:00:11:11:11' )
        s2.intf( 's2-eth1' ).setIP( '192.25.6.2', 24 )
       
        s2.intf( 's2-eth2' ).setMAC( '11:00:00:11:11:12' )
        s2.intf( 's2-eth2' ).setIP( '192.25.6.9', 24 )
        
        s3.intf( 's1-eth1' ).setMAC( '11:00:11:11:11:11' )
        s3.intf( 's3-eth1' ).setIP( '192.25.6.8', 24 )
        s3.intf( 's1-eth2' ).setMAC( '11:00:11:11:11:12' )
        s3.intf( 's3-eth2' ).setIP( '192.25.6.5', 24 )

        s4.intf( 's4-eth1' ).setMAC( '11:11:11:11:11:11' )
        s4.intf( 's4-eth1' ).setIP( '192.25.6.10', 24 )
        s4.intf( 's4-eth2' ).setMAC( '11:11:11:11:11:12' )
        s4.intf( 's4-eth2' ).setIP( '192.25.6.6', 24 )
        s4.intf( 's4-eth3' ).setMAC( '11:10:00:00:00:12' )
        s4.intf( 's4-eth3' ).setIP( '10.0.2.2', 24 )

        h1.cmd( 'route add default gw 10.0.1.2 h1-eth0' )
        h2.cmd( 'route add default gw 10.0.2.2 h2-eth0' )
       
topos = { 'mytopo': ( lambda: MyTopo() ) }