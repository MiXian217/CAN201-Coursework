from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel
def create_topology():
    # create Mininet object
    net = Mininet(topo=None, autoSetMacs=True, build=False, ipBase='10.0.1.0/24')

    # add controller
    c1 = net.addController('c1', controller=RemoteController)

    # add Host
    client = net.addHost('client', cls = Host, defaultRoute=None)
    server1 = net.addHost('server1', cls = Host, defaultRoute=None)
    server2 = net.addHost('server2', cls = Host, defaultRoute=None)

    # add switcher
    s1 = net.addSwitch('s1')
    
    # add link between sever, client and switcher
    net.addLink(client, s1)
    net.addLink(server1, s1)
    net.addLink(server2, s1)

    net.build()
    
    client.setMAC(intf='client-eth0', mac='00:00:00:00:00:03')
    server1.setMAC(intf='server1-eth0', mac='00:00:00:00:00:01')
    server2.setMAC(intf='server2-eth0', mac='00:00:00:00:00:02')
    
    client.setIP(intf='client-eth0', ip='10.0.1.5/24')
    server1.setIP(intf='server1-eth0', ip='10.0.1.2/24')
    server2.setIP(intf='server2-eth0', ip='10.0.1.3/24')
    
    net.start()
    # activate the net
    from mininet.term import makeTerm

    net.terms += makeTerm(c1)
    net.terms += makeTerm(s1)
    net.terms += makeTerm(client)
    net.terms += makeTerm(server1)
    net.terms += makeTerm(server2)


    CLI(net)


    net.stop()

if __name__ == '__main__':
    setLogLevel('info')  
    create_topology()
