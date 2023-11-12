import socket
import re
import errno
from ctypes import *
from typing import Any

libc = CDLL("libc.so.6")

READ_BUFFER_SIZE = 4096

MAC_REGEX = "^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$"
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_SDP	= 0
BT_SECURITY_LOW	= 1
BT_SECURITY_MEDIUM = 2
BT_SECURITY_HIGH = 3
BT_SECURITY_FIPS = 4

BDADDR_BREDR = 0x00
BDADDR_LE_PUBLIC = 0x01
BDADDR_LE_RANDOM = 0x02

"""
struct bt_security {
	uint8_t level;
	uint8_t key_size;
};
"""
class bt_security(Structure):
    _fields_ = [
        ("level", c_uint8),
        ("key_size", c_uint8)
    ]
    def __init__(self, level, key_size):
        self.level = level
        self.key_size = key_size
"""
struct sockaddr_l2 {
	sa_family_t	l2_family;
	unsigned short	l2_psm;
	bdaddr_t	l2_bdaddr;
	unsigned short	l2_cid;
	uint8_t		l2_bdaddr_type;
};
"""
class sockaddr_l2(Structure):
    _pack_ = 1
    _fields_ = [
        ("l2_family", c_uint16),
        ("l2_psm", c_uint16),
        ("l2_bdaddr", c_uint8 * 6),
        ("l2_cid", c_uint16),
        ("l2_bdaddr_type", c_uint8)
    ]
    def __init__(self, addr, port, addr_type):
        
        self.l2_family = (c_uint16)(socket.AF_BLUETOOTH)
        self.l2_psm = (c_uint16)(0)
        self.l2_bdaddr = (c_uint8 * 6)(*addr)
        self.l2_cid = (c_uint16)(port)
        self.l2_bdaddr_type = (c_uint8)(addr_type)

class l2capsocket:
    _sock = None    
    def __init__(self):
        r = libc.socket(
            (c_int)(socket.AF_BLUETOOTH), 
            (c_int)(socket.SOCK_SEQPACKET), 
            (c_int)(socket.BTPROTO_L2CAP)
        )
        if r == -1:
            raise Exception(f"socket() failed : {errno.errorcode[get_errno()]}")
        self._sock = r
    
    def str2ba(self,s):
        if not re.match(MAC_REGEX, s):
            raise Exception(f"invalid mac address {s}")
        return [ int(b, 16) for b in reversed(s.split(":")) ]


    def connect(self, addrport):
        addr = self.str2ba(addrport[0])
        port = int(addrport[1])
        if port > 0xffff:
            raise Exception(f"invalid port {port}")
        sockaddr = sockaddr_l2(
            addr, 
            port, 
            BDADDR_LE_PUBLIC
        )
        r = libc.connect(
            self._sock,
            byref(sockaddr),
            sockaddr.__sizeof__()
        )
        if r == -1:
            self.close()
            raise Exception(f"connect() failed : {errno.errorcode[get_errno()]}")

    def bind(self, addrport):
        addr = self.str2ba(addrport[0])
        port = int(addrport[1])
        if port > 0xffff:
            raise Exception(f"invalid port {port}")
        sockaddr = sockaddr_l2(
            addr, 
            port,
            BDADDR_BREDR
        )
        r = libc.bind(
            self._sock,
            byref(sockaddr),
            sockaddr.__sizeof__()
        )
        if r == -1:
            self.close()
            raise Exception(f"bind() failed : {errno.errorcode[get_errno()]}")
        
        btsec = bt_security(level=BT_SECURITY_LOW, key_size=0)
        r = libc.setsockopt(
            (c_int)(self._sock), 
            (c_int)(SOL_BLUETOOTH), 
            (c_int)(BT_SECURITY), 
            byref(btsec),
			btsec.__sizeof__()
        )
        if r == -1:
            self.close()
            raise Exception(f"setsockopt() failed : {errno.errorcode[get_errno()]}")

    def read(self):
        buff = (c_uint8 * READ_BUFFER_SIZE)(*[0 for x in range(0,READ_BUFFER_SIZE)])
        r = libc.read(
            self._sock,
            byref(buff),
            READ_BUFFER_SIZE
        )
        return [int(x) for x in buff[0:r]]

    def write(self, buff):
        r = libc.write(
            self._sock,
            byref((c_uint8 * len(buff))(*[int(b) for b in buff])),
            len(buff)
        )
        return r

    def close(self):
        libc.close(self._sock)
