#!/usr/bin/env python3
import logging
import random
import struct
import sys
import binascii
import os
import time
from scapy.all import *
from scapy.layers.ppp import PPP, PPP_CHAP, PPP_PAP, PPP_LCP, PPP_IPCP, PPP_LCP_Configure
from scapy.layers.ppp import PPP_LCP_MRU_Option, PPP_LCP_Magic_Number_Option, PPP_LCP_Auth_Protocol_Option

# ==================== CONFIGURATION ====================
PPPOE_IFACE = "en5"
PPPOE_AC_NAME = "scapy-pppoe-server"
PPPOE_SERVICE_NAME = "pppoe-service"
LOG_LEVEL = logging.DEBUG
AUTH_TIMEOUT = 30  # seconds to wait for authentication before timing out

# PPPoE Tag Types (RFC 2516)
PPPOE_TAG_SERVICE_NAME = 0x0101
PPPOE_TAG_AC_NAME = 0x0102
PPPOE_TAG_HOST_UNIQ = 0x0103
PPPOE_TAG_AC_COOKIE = 0x0104
# =======================================================

# ==================== SETUP LOGGING ====================
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pppoe_server_debug.log')
    ]
)
logger = logging.getLogger("PPPoEServer")
# =======================================================

# ==================== UTILITY FUNCTIONS ====================
def get_interface_mac(interface):
    """Get MAC address using Scapy"""
    try:
        return get_if_hwaddr(interface)
    except Exception as e:
        logger.error(f"Could not get MAC: {str(e)}")
        return "00:00:00:00:00:00"

def hexdump(data, prefix=""):
    """Safe hexdump for binary data"""
    try:
        hex_str = binascii.hexlify(data).decode('utf-8')
        return '\n'.join([f"{prefix}{hex_str[i:i+32]}" for i in range(0, len(hex_str), 32)])
    except Exception as e:
        return f"{prefix}Hexdump error: {str(e)}"

def parse_pppoe_discovery(pkt):
    """Manually parse PPPoE discovery packets"""
    try:
        # Ensure we have enough data for PPPoE header
        if len(pkt) < 6:
            return None

        # Parse PPPoE header
        ver_type = pkt[0]
        code = pkt[1]
        session_id = struct.unpack('!H', pkt[2:4])[0]
        length = struct.unpack('!H', pkt[4:6])[0]

        # Verify packet length
        if len(pkt) < 6 + length:
            return None

        # Parse tags
        tags = []
        tag_data = pkt[6:6+length]
        pos = 0

        while pos < len(tag_data):
            if pos + 4 > len(tag_data):
                break

            tag_type = struct.unpack('!H', tag_data[pos:pos+2])[0]
            tag_length = struct.unpack('!H', tag_data[pos+2:pos+4])[0]

            if pos + 4 + tag_length > len(tag_data):
                break

            tag_value = tag_data[pos+4:pos+4+tag_length]
            tags.append((tag_type, tag_value))
            pos += 4 + tag_length

        return {
            'version': (ver_type >> 4) & 0x0F,
            'type': ver_type & 0x0F,
            'code': code,
            'session_id': session_id,
            'length': length,
            'tags': tags
        }
    except Exception as e:
        logger.error(f"PPPoE parse error: {str(e)}")
        return None

def build_pppoe_tag(tag_type, tag_value):
    """Build PPPoE tag"""
    return struct.pack('!HH', tag_type, len(tag_value)) + tag_value

def build_pado(client_mac, server_mac, padi_data):
    """Build PADO response packet with proper tags"""
    try:
        # Parse incoming PADI
        padi = parse_pppoe_discovery(bytes(padi_data)[14:])
        if not padi:
            return None, None

        # Build PADO tags
        tags = b''

        # 1. AC-Name (correct tag type 0x0102)
        tags += build_pppoe_tag(PPPOE_TAG_AC_NAME, PPPOE_AC_NAME.encode())

        # 2. Service-Name (echo client's request or use configured name)
        client_service_name = None
        for tag_type, tag_value in padi['tags']:
            if tag_type == PPPOE_TAG_SERVICE_NAME:
                client_service_name = tag_value
                break

        if client_service_name:
            tags += build_pppoe_tag(PPPOE_TAG_SERVICE_NAME, client_service_name)
        elif PPPOE_SERVICE_NAME:
            tags += build_pppoe_tag(PPPOE_TAG_SERVICE_NAME, PPPOE_SERVICE_NAME.encode())

        # 3. AC-Cookie (security tag, required by clients)
        ac_cookie = os.urandom(16)
        tags += build_pppoe_tag(PPPOE_TAG_AC_COOKIE, ac_cookie)

        # 4. Host-Uniq (echo client's value)
        for tag_type, tag_value in padi['tags']:
            if tag_type == PPPOE_TAG_HOST_UNIQ:
                tags += build_pppoe_tag(PPPOE_TAG_HOST_UNIQ, tag_value)
                break

        # Build PPPoE header
        pppoe_header = struct.pack('!BBHH',
                                  (1 << 4) | 1,  # ver=1, type=1
                                  0x07,           # PADO code
                                  0,              # session ID=0
                                  len(tags))      # length

        # Build Ethernet frame
        eth_header = struct.pack('!6s6sH',
                                binascii.unhexlify(client_mac.replace(':', '')),
                                binascii.unhexlify(server_mac.replace(':', '')),
                                0x8863)           # PPPoE Discovery

        return eth_header + pppoe_header + tags, ac_cookie
    except Exception as e:
        logger.error(f"PADO build error: {str(e)}")
        return None, None

def build_pads(client_mac, server_mac, session_id, host_uniq=None):
    """Build PADS response with Host-Uniq tag if provided"""
    try:
        tags = b''
        # Service-Name tag (required)
        tags += build_pppoe_tag(PPPOE_TAG_SERVICE_NAME, PPPOE_SERVICE_NAME.encode())

        # Add Host-Uniq if provided
        if host_uniq:
            tags += build_pppoe_tag(PPPOE_TAG_HOST_UNIQ, host_uniq)

        # Build PPPoE header
        pppoe_header = struct.pack('!BBHH',
                                  (1 << 4) | 1,  # ver=1, type=1
                                  0x65,           # PADS code
                                  session_id,     # session ID
                                  len(tags))      # length

        # Build Ethernet frame
        eth_header = struct.pack('!6s6sH',
                                binascii.unhexlify(client_mac.replace(':', '')),
                                binascii.unhexlify(server_mac.replace(':', '')),
                                0x8863)           # PPPoE Discovery

        return eth_header + pppoe_header + tags
    except Exception as e:
        logger.error(f"PADS build error: {str(e)}")
        return None
# ============================================================

# ==================== SESSION MANAGEMENT ====================
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.pending_sessions = {}  # Track pending sessions with AC-Cookie
        self.session_cookies = {}   # Track AC-Cookies for established sessions
        self.last_lcp = {}          # Track last LCP time per client
        self.session_timers = {}    # Track session creation time
        self.auth_methods = {}      # Track authentication methods per session

    def create_session(self, client_mac, session_id=None):
        """Create a new session with unique ID"""
        if not session_id:
            session_id = random.randint(0x0001, 0xfffe)
        self.sessions[client_mac] = session_id
        self.session_timers[client_mac] = time.time()

        # Store AC-Cookie for this session
        if client_mac in self.pending_sessions:
            self.session_cookies[client_mac] = self.pending_sessions[client_mac]
            del self.pending_sessions[client_mac]

        return session_id

    def get_session_id(self, client_mac):
        return self.sessions.get(client_mac)

    def terminate_session(self, client_mac):
        if client_mac in self.sessions:
            del self.sessions[client_mac]
        if client_mac in self.pending_sessions:
            del self.pending_sessions[client_mac]
        if client_mac in self.session_cookies:
            del self.session_cookies[client_mac]
        if client_mac in self.session_timers:
            del self.session_timers[client_mac]
        if client_mac in self.auth_methods:
            del self.auth_methods[client_mac]

    def get_session_cookie(self, client_mac):
        """Get AC-Cookie for an established session"""
        return self.session_cookies.get(client_mac)

    def check_session_timeout(self, client_mac):
        """Check if session has timed out waiting for authentication"""
        if client_mac in self.session_timers:
            return (time.time() - self.session_timers[client_mac]) > AUTH_TIMEOUT
        return True

    def set_auth_method(self, client_mac, method):
        """Set authentication method for session"""
        self.auth_methods[client_mac] = method

    def get_auth_method(self, client_mac):
        """Get authentication method for session"""
        return self.auth_methods.get(client_mac)
# ============================================================

# ==================== PACKET HANDLERS ====================
def handle_padi(pkt, session_manager, server_mac):
    """Handle PPPoE Active Discovery Initiation"""
    try:
        client_mac = pkt[Ether].src
        logger.info(f"Received PADI from {client_mac}")

        # Build PADO response with proper tags
        pado, ac_cookie = build_pado(client_mac, server_mac, pkt)
        if not pado:
            logger.error("Failed to build PADO")
            return

        # Store AC-Cookie for session validation
        session_manager.pending_sessions[client_mac] = ac_cookie

        # Send raw packet
        sendp(Raw(pado), iface=PPPOE_IFACE, verbose=0)
        logger.info(f"Sent PADO to {client_mac}")
        logger.debug(f"Generated AC-Cookie: {binascii.hexlify(ac_cookie).decode()}")

    except Exception as e:
        logger.error(f"Error handling PADI: {str(e)}")

def handle_padr(pkt, session_manager, server_mac):
    """Handle PPPoE Active Discovery Request"""
    try:
        client_mac = pkt[Ether].src
        logger.info(f"Received PADR from {client_mac}")

        # Parse PADR manually to get tags
        padr = parse_pppoe_discovery(bytes(pkt)[14:])
        if not padr:
            logger.error("Failed to parse PADR")
            return

        # Validate AC-Cookie
        ac_cookie = None
        for tag_type, tag_value in padr['tags']:
            if tag_type == PPPOE_TAG_AC_COOKIE:
                ac_cookie = tag_value
                break

        if not ac_cookie:
            logger.error("PADR missing AC-Cookie")
            return

        # Extract Host-Uniq for PADS response
        host_uniq = None
        for tag_type, tag_value in padr['tags']:
            if tag_type == PPPOE_TAG_HOST_UNIQ:
                host_uniq = tag_value
                break

        # Check if we have a session already established
        if client_mac in session_manager.sessions:
            session_id = session_manager.get_session_id(client_mac)
            logger.info(f"Resending PADS for existing session {session_id}")

            # Build and send PADS with Host-Uniq
            pads = build_pads(client_mac, server_mac, session_id, host_uniq)
            if not pads:
                logger.error("Failed to build PADS")
                return

            sendp(Raw(pads), iface=PPPOE_IFACE, verbose=0)
            logger.info(f"Resent PADS to {client_mac} for session ID {session_id}")
            return

        # Check pending sessions
        if client_mac not in session_manager.pending_sessions:
            logger.error("No pending session for client")
            return

        if session_manager.pending_sessions[client_mac] != ac_cookie:
            logger.error("Invalid AC-Cookie in PADR")
            return

        # Create new session after validation
        session_id = session_manager.create_session(client_mac)

        # Build PADS response with Host-Uniq
        pads = build_pads(client_mac, server_mac, session_id, host_uniq)
        if not pads:
            logger.error("Failed to build PADS")
            return

        # Send raw packet
        sendp(Raw(pads), iface=PPPOE_IFACE, verbose=0)
        logger.info(f"Sent PADS to {client_mac} with session ID {session_id}")

    except Exception as e:
        logger.error(f"Error handling PADR: {str(e)}")

def handle_padt(pkt, session_manager):
    """Handle PPPoE Active Discovery Terminate"""
    try:
        client_mac = pkt[Ether].src
        logger.info(f"Received PADT from {client_mac}")
        session_manager.terminate_session(client_mac)

    except Exception as e:
        logger.error(f"Error handling PADT: {str(e)}")

# ==================== PACKET HANDLERS ====================
def handle_ppp(pkt, session_manager, server_mac):
    """Handle PPP session packets"""
    try:
        # Check for required layers
        if not (PPPoE in pkt and Ether in pkt and PPP in pkt):
            return

        # Enhanced logging
        logger.debug(f"Received PPP session packet from {pkt[Ether].src}")
        logger.debug(pkt.summary())
        logger.debug(f"Packet layers: {pkt.layers()}")
        logger.debug(f"PPP proto: 0x{pkt[PPP].proto:04x}")

        pppoe = pkt[PPPoE]
        if pppoe.code != 0x00:  # Only handle session data
            return

        client_mac = pkt[Ether].src
        session_id = session_manager.get_session_id(client_mac)

        if not session_id:
            logger.warning(f"Unknown session from {client_mac}")
            return

        # Check for session timeout
        if session_manager.check_session_timeout(client_mac):
            logger.warning(f"Session timeout for {client_mac}")
            session_manager.terminate_session(client_mac)
            return

        # LCP handling - manual dissection
        if pkt[PPP].proto == 0xc021:
            logger.debug("PPP protocol is LCP (0xc021)")

            # Extract raw LCP data
            lcp_data = bytes(pkt[PPP].payload)
            code = lcp_data[0]
            lcp_id = lcp_data[1]
            length = struct.unpack('!H', lcp_data[2:4])[0]
            options_data = lcp_data[4:4+(length-4)] if length > 4 else b''

            logger.info(f"LCP packet: code={code}, id={lcp_id}, length={length}")

            # Skip duplicate LCP requests within 5 seconds
            current_time = time.time()
            if client_mac in session_manager.last_lcp and current_time - session_manager.last_lcp[client_mac] < 5:
                logger.debug(f"Skipping duplicate LCP request from {client_mac}")
                return
            session_manager.last_lcp[client_mac] = current_time

            if code == 1:  # Configure-Request from client
                logger.info(f"LCP Configure-Request from {client_mac} (ID: {lcp_id})")
                logger.debug(f"Options data: {binascii.hexlify(options_data).decode()}")

                # 1. Send Configure-Ack with same options
                ack_data = b'\x02' + lcp_data[1:length]  # Change code to 2 (Ack)
                lcp_ack = (
                    Ether(dst=client_mac, src=server_mac) /
                    PPPoE(sessionid=session_id) /
                    PPP(proto=0xc021) /
                    Raw(load=ack_data)
                )
                sendp(lcp_ack, iface=PPPOE_IFACE, verbose=0)
                logger.info(f"Sent LCP Configure-Ack to {client_mac}")
                logger.debug(lcp_ack.summary())

                # 2. Send our own Configure-Request with authentication protocol
                magic_number = random.getrandbits(32)
                lcp_req = (
                    Ether(dst=client_mac, src=server_mac) /
                    PPPoE(sessionid=session_id) /
                    PPP(proto=0xc021) /
                    PPP_LCP_Configure(
                        code=1,  # Configure-Request
                        id=2,    # Different ID than client's
                        options=[
                            PPP_LCP_MRU_Option(max_recv_unit=1492),
                            PPP_LCP_Magic_Number_Option(magic_number=magic_number),
                            PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc023, data=b'')
                        ]
                    )
                )
                sendp(lcp_req, iface=PPPOE_IFACE, verbose=0)
                logger.info(f"Sent Server LCP Configure-Request to {client_mac}")
                logger.debug(lcp_req.summary())

            elif code == 2:  # Configure-Ack from client
                logger.info(f"Received LCP Configure-Ack from {client_mac}")
                logger.info("LCP negotiation complete, ready for authentication")

            elif code == 3:  # Configure-Nak
                logger.info(f"Received LCP Configure-Nak from {client_mac}")
                # Handle negotiation if needed

            elif code == 4:  # Configure-Reject
                logger.info(f"Received LCP Configure-Reject from {client_mac}")
                # Handle rejected options if needed

        # PAP authentication handling
        elif pkt[PPP].proto == 0xc023:
            logger.debug("PPP protocol is PAP (0xc023)")

            # Extract raw PAP data
            pap_data = bytes(pkt[PPP].payload)
            code = pap_data[0]
            pap_id = pap_data[1]
            length = struct.unpack('!H', pap_data[2:4])[0]

            # Parse username and password (length-prefixed strings)
            user_len = pap_data[4]
            username = pap_data[5:5+user_len].decode('utf-8', 'ignore')
            pass_len = pap_data[5+user_len]
            password = pap_data[6+user_len:6+user_len+pass_len].decode('utf-8', 'ignore')

            if code == 1:  # Authenticate-Request
                logger.info(f"PAP Authentication: Username='{username}' Password='{password}'")

                # Send PAP success response
                pap_ack = (
                    Ether(dst=client_mac, src=server_mac) /
                    PPPoE(sessionid=session_id) /
                    PPP(proto=0xc023) /
                    PPP_PAP(code=2, id=pap_id, len=5+len("OK"), message="OK")
                )
                sendp(pap_ack, iface=PPPOE_IFACE, verbose=0)
                logger.info("Sent PAP Authentication-Ack")
                logger.debug(pap_ack.summary())

    except Exception as e:
        logger.error(f"Error handling PPP session: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

# ==================== MAIN FUNCTION ====================
def main():
    # Get server MAC address
    server_mac = get_interface_mac(PPPOE_IFACE)
    logger.info(f"Starting PPPoE Server on {PPPOE_IFACE}")
    logger.info(f"Interface MAC: {server_mac}")

    # Initialize session manager
    session_manager = SessionManager()

    # Configure Scapy
    conf.iface = PPPOE_IFACE
    conf.use_pcap = True

    # Packet handling function
    def packet_handler(pkt):
        try:
            # Skip packets sent by ourselves
            if Ether in pkt and pkt[Ether].src == server_mac:
                return

            # Log raw packet for analysis
            if Ether in pkt:
                logger.debug(f"Received packet from {pkt[Ether].src}: {len(pkt)} bytes")
                logger.debug(hexdump(bytes(pkt), "  "))

                # PPPoE Discovery packets
                if pkt[Ether].type == 0x8863:
                    # Manually parse PPPoE discovery
                    pppoe = parse_pppoe_discovery(bytes(pkt)[14:])
                    if not pppoe:
                        return

                    if pppoe['code'] == 0x09:  # PADI
                        handle_padi(pkt, session_manager, server_mac)
                    elif pppoe['code'] == 0x19:  # PADR
                        handle_padr(pkt, session_manager, server_mac)
                    elif pppoe['code'] == 0xa7:  # PADT
                        handle_padt(pkt, session_manager)

                # PPPoE Session packets
                elif pkt[Ether].type == 0x8864 and PPPoE in pkt:
                    pppoe = pkt[PPPoE]
                    if pppoe.code == 0x00:  # Session data
                        handle_ppp(pkt, session_manager, server_mac)

        except Exception as e:
            logger.error(f"Packet handling error: {str(e)}")

    # Start sniffing
    try:
        logger.info("Starting packet capture...")
        sniff(
            iface=PPPOE_IFACE,
            prn=packet_handler,
            filter="ether proto 0x8863 or ether proto 0x8864",
            store=0,
            promisc=True
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Sniffing error: {str(e)}")
    finally:
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    main()
