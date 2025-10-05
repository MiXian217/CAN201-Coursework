from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
                Add a flow entry
                :param datapath: Switch index
                :param priority:
                :param match:
                :param actions:
                :param buffer_id:
                :return:
                """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow1(self, datapath, priority, match, actions, buffer_id=None):
        """
                Add a flow entry v2
                :param datapath: Switch index
                :param priority:
                :param match:
                :param actions:
                :param buffer_id:
                :return:
                """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Process the packet_in massage
        :param ev:
        :return:
        """
        # mac and ips
        client = {'mac': '00:00:00:00:00:03', 'ip': '10.0.1.5'}
        server1 = {'mac': '00:00:00:00:00:01', 'ip': '10.0.1.2'}
        server2 = {'mac': '00:00:00:00:00:02', 'ip': '10.0.1.3'}

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # get datapath ID to identify Openflow switches
        dpid = format(datapath.id, "d").zfill(16)  # port id of switch
        self.mac_to_port.setdefault(dpid, {})

        # analysis the receiveed packet using data library
        pkt = packet.Packet(msg.data)  # pass the data
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # get protocol of ethernet layers
        dst = eth.dst  # get destination mac address
        src = eth.src  # get source mac address

        in_port = msg.match['in_port']  # get the received port number from packet_in message
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port  # bind src mac and in_port together

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore LLDP packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:  # 0x0806  ARP: Address Resolution Protocol
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst, eth_src=src)

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            # tcp_pkt = pkt.get_protocol(tcp.tcp)
            ip_src = ipv4_pkt.src
            ip_dst = ipv4_pkt.dst

            self.logger.info(f"Packet_in dpid: {dpid}, from src: {src}, to dst: {dst}, in_port: {in_port}")
            # if the destination mac address is already learned, decide which port to output the packet, otherwise FLOOD
            if ip_src == client['ip']:
                if server2['mac'] in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][server2['mac']]
                else:  # if OFPP_FLOOD, send to all port
                    out_port = ofproto.OFPP_FLOOD
                    self.logger.info(f"<<<FLOOD>>>")
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)
                actions = [parser.OFPActionSetField(eth_dst=server2['mac']),
                           parser.OFPActionSetField(ipv4_dst=server2['ip']),
                           parser.OFPActionOutput(port=out_port)]

            if ip_src == server2['ip']:
                if client['mac'] in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][client['mac']]
                else:  # if OFPP_FLOOD, send to all port
                    out_port = ofproto.OFPP_FLOOD
                    self.logger.info(f"<<<FLOOD>>>")
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)
                actions = [parser.OFPActionSetField(eth_src=server1['mac']),
                           parser.OFPActionSetField(ipv4_src=server1['ip']),
                           parser.OFPActionOutput(port=out_port)]

            # install a flow to avoid packet_in next time
            try:
                # verify if we have a valid buffer_id, if yes, avoid sending both flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow1(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow1(datapath, 1, match, actions)
            except:
                pass  # if detect match referenced before define, just ignore

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            # build a packet_out message
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            self.logger.info(
                f"Packet_out dpid: {dpid}, in_port: {in_port}, actions: {actions}, buffer_id: {msg.buffer_id}")
            self.logger.info(f"----------------------------------------------------------------------------------")
            # send flow table
            datapath.send_msg(out)

        else:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            # if OFPP_FLOOD, send to all port
            actions = [parser.OFPActionOutput(
                out_port)]  # a packet_out message to specify a switch port that you want to send the packet out of.

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            # build a packet_out message
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            # send flow table
            datapath.send_msg(out)
