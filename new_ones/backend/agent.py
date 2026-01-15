"""
Network Monitoring Agent
Lightweight agent for capturing and analyzing network traffic
"""

import pyshark
import time
import requests
import json
import os
from datetime import datetime
from collections import defaultdict
import threading
import argparse

class NetworkAgent:
    """Lightweight network monitoring agent"""
    
    def __init__(self, agent_id, interface='eth0', api_url='http://localhost:5000/api'):
        """
        Initialize the network agent
        
        Args:
            agent_id (str): Unique identifier for this agent
            interface (str): Network interface to monitor
            api_url (str): Backend API URL
        """
        self.agent_id = agent_id
        self.interface = interface
        self.api_url = api_url
        self.token = None
        self.running = False
        
        # Traffic statistics
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_count = defaultdict(int)
        self.connection_tracker = defaultdict(int)
        
        # TCP flags tracking
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        
        # Packet size tracking
        self.packet_sizes = []
        
        # Timing
        self.start_time = None
        self.last_report_time = None
        self.report_interval = 5  # Report every 5 seconds
        
        print(f"🔧 Agent {self.agent_id} initialized on interface {self.interface}")
    
    def authenticate(self, username, password):
        """Authenticate with the backend API"""
        try:
            response = requests.post(
                f"{self.api_url}/auth/login",
                json={'email': username, 'password': password},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access_token')
                print(f"✓ Agent {self.agent_id} authenticated successfully")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def process_packet(self, packet):
        """
        Process a captured packet
        
        Args:
            packet: PyShark packet object
        """
        try:
            self.packet_count += 1
            
            # Get packet size
            try:
                packet_size = int(packet.length)
                self.byte_count += packet_size
                self.packet_sizes.append(packet_size)
            except:
                packet_size = 0
            
            # Track protocol
            if hasattr(packet, 'highest_layer'):
                protocol = packet.highest_layer
                self.protocol_count[protocol] += 1
            
            # Track TCP flags
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                    self.syn_count += 1
                if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1':
                    self.ack_count += 1
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                    self.fin_count += 1
                if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1':
                    self.rst_count += 1
            
            # Track connections
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src if hasattr(packet.ip, 'src') else None
                dst_ip = packet.ip.dst if hasattr(packet.ip, 'dst') else None
                
                if src_ip and dst_ip:
                    connection = f"{src_ip}-{dst_ip}"
                    self.connection_tracker[connection] += 1
            
        except Exception as e:
            print(f"⚠ Packet processing error: {e}")
    
    def calculate_statistics(self):
        """Calculate traffic statistics"""
        current_time = time.time()
        
        if self.start_time is None:
            self.start_time = current_time
            self.last_report_time = current_time
        
        # Time since last report
        time_diff = current_time - self.last_report_time
        
        if time_diff == 0:
            time_diff = 1
        
        # Calculate rates
        packet_rate = self.packet_count / time_diff
        byte_rate = self.byte_count / time_diff
        
        # Packet size statistics
        avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        max_packet_size = max(self.packet_sizes) if self.packet_sizes else 0
        min_packet_size = min(self.packet_sizes) if self.packet_sizes else 0
        
        # Most common protocol
        most_common_protocol = max(self.protocol_count, key=self.protocol_count.get) if self.protocol_count else 'TCP'
        
        # Unique IPs
        unique_connections = len(self.connection_tracker)
        
        stats = {
            'agent_id': self.agent_id,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'packet_rate': round(packet_rate, 2),
            'byte_rate': round(byte_rate, 2),
            'protocol': most_common_protocol,
            'avg_packet_size': round(avg_packet_size, 2),
            'max_packet_size': max_packet_size,
            'min_packet_size': min_packet_size,
            'syn_count': self.syn_count,
            'ack_count': self.ack_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'unique_connections': unique_connections,
            'flow_duration': round(time_diff, 2)
        }
        
        return stats
    
    def report_statistics(self):
        """Send statistics to backend API"""
        try:
            stats = self.calculate_statistics()
            
            headers = {'Authorization': f'Bearer {self.token}'}
            
            response = requests.post(
                f"{self.api_url}/traffic/submit",
                json=stats,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                print(f"✓ [{self.agent_id}] Reported: {stats['packet_count']} packets, "
                      f"{stats['packet_rate']:.2f} pkt/s")
            else:
                print(f"⚠ Report failed: {response.status_code}")
            
            # Reset counters
            self.reset_counters()
            
        except Exception as e:
            print(f"✗ Report error: {e}")
    
    def reset_counters(self):
        """Reset traffic counters after reporting"""
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_count.clear()
        self.connection_tracker.clear()
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.packet_sizes.clear()
        self.last_report_time = time.time()
    
    def reporting_thread(self):
        """Background thread for periodic reporting"""
        while self.running:
            time.sleep(self.report_interval)
            if self.packet_count > 0:
                self.report_statistics()
    
    def start_monitoring(self):
        """Start monitoring network traffic"""
        self.running = True
        self.start_time = time.time()
        self.last_report_time = time.time()
        
        # Start reporting thread
        reporter = threading.Thread(target=self.reporting_thread, daemon=True)
        reporter.start()
        
        print(f"🔍 Agent {self.agent_id} started monitoring on {self.interface}")
        print("Press Ctrl+C to stop...")
        
        try:
            # Start packet capture
            capture = pyshark.LiveCapture(interface=self.interface)
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                self.process_packet(packet)
                
        except KeyboardInterrupt:
            print("\n⏹ Stopping agent...")
            self.running = False
        except Exception as e:
            print(f"✗ Monitoring error: {e}")
            self.running = False
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print(f"⏹ Agent {self.agent_id} stopped")


def main():
    """Main entry point for the agent"""
    parser = argparse.ArgumentParser(description='GarudaRush Network Monitoring Agent')
    parser.add_argument('--agent-id', required=True, help='Unique agent identifier')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--api-url', default='http://localhost:5000/api', help='Backend API URL')
    parser.add_argument('--username', required=True, help='API username')
    parser.add_argument('--password', required=True, help='API password')
    
    args = parser.parse_args()
    
    # Create agent
    agent = NetworkAgent(
        agent_id=args.agent_id,
        interface=args.interface,
        api_url=args.api_url
    )
    
    # Authenticate
    if not agent.authenticate(args.username, args.password):
        print("Failed to authenticate. Exiting.")
        return
    
    # Start monitoring
    agent.start_monitoring()


if __name__ == '__main__':
    main()