#!/usr/bin/env python3
"""
NetGuard AI - Packet Capture Service (Redis Version)
Captures network traffic using Scapy and sends to Redis
"""

import os
import sys
import json
import socket
import logging
import signal
from datetime import datetime
from configparser import ConfigParser

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
import redis

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/netguard/capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('netguard-capture')

class PacketCapture:
    def __init__(self, config_path='/etc/netguard/netguard.conf'):
        self.config = ConfigParser()
        self.config.read(config_path)
        
        self.interface = self.config.get('capture', 'interface', fallback='eth0')
        
        # Redis connection
        redis_host = self.config.get('redis', 'host', fallback='localhost')
        redis_port = self.config.getint('redis', 'port', fallback=6379)
        redis_db = self.config.getint('redis', 'db', fallback=0)
        
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=False)
        self.redis_queue = 'netguard:capture'
        
        self.running = False
        self.dns_cache = {}
        
    def get_domain(self, packet):
        """Extract domain name from packet"""
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                qname = packet[DNSQR].qname
                if qname:
                    return qname.decode().rstrip('.')
            except:
                pass
        
        dst_ip = packet[IP].dst if packet.haslayer(IP) else None
        if dst_ip and dst_ip in self.dns_cache:
            return self.dns_cache[dst_ip]
        
        if dst_ip:
            try:
                domain = socket.getnameinfo((dst_ip, 0), socket.NI_NAMEREQD)[0]
                if domain and domain != dst_ip:
                    self.dns_cache[dst_ip] = domain
                    return domain
            except:
                pass
        
        return "-"
    
    def extract_packet_info(self, packet):
        """Extract relevant info from packet"""
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        
        info = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': 'OTHER',
            'src_port': None,
            'dst_port': None,
            'domain': '-',
            'bytes_in': len(packet),
            'bytes_out': 0,
            'flags': None,
        }
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            info['protocol'] = 'TCP'
            info['src_port'] = tcp_layer.sport
            info['dst_port'] = tcp_layer.dport
            info['flags'] = str(tcp_layer.flags)
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            info['protocol'] = 'UDP'
            info['src_port'] = udp_layer.sport
            info['dst_port'] = udp_layer.dport
            
            if info['dst_port'] == 53 or info['src_port'] == 53:
                info['domain'] = self.get_domain(packet)
        
        elif packet.haslayer(ICMP):
            info['protocol'] = 'ICMP'
            info['icmp_type'] = packet[ICMP].type
        
        if info['dst_port'] in [80, 443]:
            info['domain'] = self.get_domain(packet)
        
        return info
    
    def packet_handler(self, packet):
        """Handle captured packet"""
        try:
            info = self.extract_packet_info(packet)
            if info:
                # Push to Redis queue
                self.redis_client.lpush(self.redis_queue, json.dumps(info))
                # Trim queue to prevent memory issues (keep last 10000)
                self.redis_client.ltrim(self.redis_queue, 0, 9999)
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    def start(self):
        """Start capture"""
        logger.info(f"Starting packet capture on {self.interface}")
        
        # Test Redis connection
        try:
            self.redis_client.ping()
            logger.info("Connected to Redis")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            sys.exit(1)
        
        self.running = True
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                promisc=True
            )
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop capture"""
        logger.info("Stopping capture...")
        self.running = False
        logger.info("Capture stopped")

def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}")
    capture.stop()
    sys.exit(0)

if __name__ == '__main__':
    capture = PacketCapture()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    capture.start()
