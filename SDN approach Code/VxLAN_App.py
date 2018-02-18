'''

@author Ananthram, Shishir
'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import json
import threading 
import sys 
import select
import os

global vtep
global vtep_local
vtep ={}


#Function to delete paths 
def delete_mod(datapath):
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    
    
    idle_timeout = hard_timeout = 0
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    match = None
    actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
    req = ofp_parser.OFPFlowMod(datapath=datapath, table_id = 0,
                                command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                buffer_id=buffer_id,
                                match=match, instructions=inst)
    datapath.send_msg(req)
    
    req = ofp_parser.OFPFlowMod(datapath=datapath, table_id = 1,
                                command=ofp.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                buffer_id=buffer_id,
                                match=match, instructions=inst)
    datapath.send_msg(req)
    


    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    match = parser.OFPMatch()
    inst = [parser.OFPInstructionGotoTable(1)]
    mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
    datapath.send_msg(mod)
            
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(
    datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
    datapath.send_msg(mod)
            
            
vtep_local = {

    "0x5a69cbf38842": {"mac_vni_to_port": {}},#DC-West
    "0x1ea6b7fe504f": {"mac_vni_to_port": {}},#DC-East
    "0xe980ff91541": {"mac_vni_to_port": {}}#DC-North
    
        }

#Function to Reload paths 		
def VtepReload():
        
     
    for temp in vtep_local:
        #print temp
        
        datapath = vtep_local[temp]['datapath']
        delete_mod(datapath)
        
        #print datapath
        dpid = datapath.id
        dpid_hex = hex(dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        for vni, ports in vtep[dpid_hex]["vni_locport"].items():
                for port in ports:
                    match = parser.OFPMatch(in_port=port)
                    actions = [parser.NXActionSetTunnel(tun_id=int(vni))]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(1)] 
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst)
                    datapath.send_msg(mod)
                   


def load_vtep_first(json_filename):
    with open(json_filename) as fp:
        global vtep
        vtep = json.load(fp)

def load_vtep(json_filename):
    with open(json_filename) as fp:
        global vtep
        vtep = json.load(fp)
        print ('Change Detected' )
        VtepReload()

#Function to check changes in configuration 
def periodic_load_json(json_filename):
        mtime = os.path.getmtime(json_filename)
        if mtime != periodic_load_json.m_time:
            load_vtep(json_filename)
        periodic_load_json.m_time = mtime
        timer = threading.Timer(2.0, periodic_load_json, [json_filename])
        timer.start()


def load_json(json_filename):
    periodic_load_json.m_time = 0
    timer = threading.Timer(8.0, periodic_load_json, [json_filename])
    timer.start()
    
    
    
#Event hanlder for newly connected switch  
class connection_handler(threading.Thread):
    
    def __init__(self, ev):
        threading.Thread.__init__(self)
        self.ev = ev
    
    def run(self):
            global vtep
            datapath = self.ev.msg.datapath
                        
            dpid = datapath.id
            dpid_hex = hex(dpid)
            vtep_local[dpid_hex]["datapath"] = datapath            
            print("Switch with DPID = ", dpid_hex, "is up and connected to the Controller..")
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
        
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(1)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
            datapath.send_msg(mod)
         
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
            datapath.send_msg(mod)
            
            for vni, ports in vtep[dpid_hex]["vni_locport"].items():
                for port in ports:
                     
                    match = parser.OFPMatch(in_port=port)
                    actions = [parser.NXActionSetTunnel(tun_id=int(vni))]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(1)]  
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst)
                    datapath.send_msg(mod)


#Event hanlder for packet In                   
class packetIN_handle(threading.Thread):
    def __init__(self, ev):
        threading.Thread.__init__(self)
        self.ev = ev
    
    def run(self):
        global vtep
        msg = self.ev.msg
        datapath = msg.datapath
        
        dpid = datapath.id
        dpid_hex = hex(dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # ignore LLDP packet

        in_port = msg.match['in_port']
        try:
            vni = msg.match['tunnel_id']  # Only packets with VNI Tag set reach the controller
        except KeyError as e:
            #print 'KeyError' , e
            return
            
        print("Received a packet from {0} on port={1}, with VNI ID={2} from eth_src={3} to eth_dst={4}".format(dpid_hex,in_port,vni,eth.src,eth.dst))
                                                                                                               
        
        vtep_local[dpid_hex]["mac_vni_to_port"][(eth.src, vni)] = in_port
        vxlan_ports = vtep[dpid_hex]["vni_vxlanport"][str(vni)][:]
        local_ports = vtep[dpid_hex]["vni_locport"][str(vni)][:]
        if eth.dst == 'ff:ff:ff:ff:ff:ff':
            
            if in_port in vxlan_ports:  # External VTEP has sent broadcast packet, so broadcast on local ports.
                print("Received Packet on VxLAN port ; Broadcasting on Local Ports....")
                for port in local_ports:
                    actions = [parser.OFPActionOutput(port=port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=(in_port),
                                              actions=actions, data=pkt)
                    datapath.send_msg(out)
                    
            else:  #
                print("Sending on all matching local ports other than in_port..")
                local_ports.remove(in_port)
                for port in local_ports:  # Forward on all matching local ports

                    actions = [parser.OFPActionOutput(port=port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=(in_port),
                                              actions=actions, data=pkt)
                    datapath.send_msg(out)
                    print("{0}: {1} Packet src={2}, destination={3}, output={4}".format(dpid_hex, 0, eth.src,
                                                                                        eth.dst, port))
                print("Sending on all matching VxLAN tunnels with VNI tagged..")
                for port in vxlan_ports:  # Multicast operation

                    actions = [parser.NXActionSetTunnel(tun_id=int(vni)), parser.OFPActionOutput(port=port)]
                    
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,actions=actions, data=pkt)
                    
                    datapath.send_msg(out)
                    
                    print(
                    "{0} : {1} Packet output in_port={2} setTunnelId={3} out_port={4}".format(dpid, 0, in_port, vni,
                                                                                              port))

        else:  # Unicast message
            
            try:
                global vtep
                out_port = vtep_local[dpid_hex]["mac_vni_to_port"][(eth.dst, vni)]
            except KeyError as nomatch:
                return
            
            match = parser.OFPMatch(tunnel_id=int(vni), eth_dst=eth.dst)
            actions = [parser.OFPActionOutput(port=out_port)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                    instructions=inst)
            datapath.send_msg(mod)
         
            match = parser.OFPMatch(tunnel_id=int(vni), eth_dst=eth.src)
            actions = [parser.OFPActionOutput(port=in_port)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                    instructions=inst)
            datapath.send_msg(mod)
            
            local_ports = vtep[dpid_hex]["vni_locport"][str(vni)][:]
            if in_port  in local_ports:
                actions = [parser.NXActionSetTunnel(tun_id=int(vni)),parser.OFPActionOutput(port=out_port)]
            else:
                actions = [parser.OFPActionOutput(port=out_port)]
            
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                      actions=actions, data=pkt)
            datapath.send_msg(out)
                 


#Thread for user interface, but did not workout
class user(threading.Thread):    
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        while 1: 
            oper = 'some Oper' #raw_input ("Add or delete")
            print oper

			
			
			
			
#Main RYU App
class VTEP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VTEP, self).__init__(*args, **kwargs)
        load_vtep_first('Tenant_config.json')
        load_json('Tenant_config.json')
    
    while sys.stdin in select.select([sys.stdin], [], [], 1)[0]: # User Thread 
        line = sys.stdin.readline()
        if line:
            u_thread = user()
            u_thread.start()
        else: # an empty line means stdin has been closed
            print('eof')
            exit(0)
    else:
        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def _connection_up_handler(self, ev): 
            t=connection_handler(ev)
            t.start()
        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
            t1=packetIN_handle(ev)
            t1.start()
        #something_else()
        
        
