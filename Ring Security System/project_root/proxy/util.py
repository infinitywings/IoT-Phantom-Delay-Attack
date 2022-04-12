import socket,struct,typing
from ipaddress import IPv4Address


def original_addr(csock: socket.socket) -> typing.Tuple[str, int]:
    SO_ORIGINAL_DST = 80
    SOL_IPV6 = 41

    is_ipv4 = "." in csock.getsockname()[0]
    if is_ipv4:
        dst = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, raw_ip = struct.unpack_from("!2xH4s", dst)
        ip = socket.inet_ntop(socket.AF_INET, raw_ip)
    else:
        dst = csock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
        port, raw_ip = struct.unpack_from("!2xH4x16s", dst)
        ip = socket.inet_ntop(socket.AF_INET6, raw_ip)
    return ip, port

def isLocal(address):
    # gateway_ip, net_if = netifaces.gateways()['default'][netifaces.AF_INET]
    # addr_obj = netifaces.ifaddresses(net_if)[netifaces.AF_INET][0]
    if IPv4Address(address).is_private:
        return True
    else:
        return False

def longlive(addr,port):
    return True


def device_type(length):
    if (388 < length) and (393 > length):
        return 'third_reality'
