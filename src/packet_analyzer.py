from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime
from typing import Dict, Optional, Any, Tuple
from colorama import Fore, Style

class PacketAnalyzer:
    """패킷 분석 클래스"""
    
    @staticmethod
    def parse_ip_header(packet: IP) -> Dict[str, Any]:
        """IP 헤더 파싱"""
        return {
            'version': packet.version,
            'ihl': packet.ihl,
            'tos': packet.tos,
            'len': packet.len,
            'id': packet.id,
            'flags': packet.flags,
            'frag': packet.frag,
            'ttl': packet.ttl,
            'proto': packet.proto,
            'chksum': packet.chksum,
            'src': packet.src,
            'dst': packet.dst,
            'options': packet.options
        }
    
    @staticmethod
    def identify_protocol(packet: IP) -> str:
        """프로토콜 식별"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return f'Other({packet.proto})'
    
    @staticmethod
    def calculate_packet_size(packet: IP) -> Dict[str, int]:
        """패킷 크기 계산"""
        return {
            'total_size': len(packet),
            'header_size': packet.ihl * 4,
            'payload_size': len(packet.payload)
        }
    
    @staticmethod
    def format_timestamp(timestamp: datetime) -> Dict[str, str]:
        """타임스탬프 처리"""
        return {
            'iso_format': timestamp.isoformat(),
            'date': timestamp.strftime('%Y-%m-%d'),
            'time': timestamp.strftime('%H:%M:%S.%f'),
            'unix_timestamp': str(timestamp.timestamp())
        }
    
    @staticmethod
    def analyze_tcp_ports(packet: TCP) -> Dict[str, Any]:
        """TCP 포트 정보 분석"""
        well_known_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
            3306: 'MySQL', 5432: 'PostgreSQL'
        }
        
        return {
            'source_port': {
                'number': packet.sport,
                'service': well_known_ports.get(packet.sport, 'Unknown')
            },
            'dest_port': {
                'number': packet.dport,
                'service': well_known_ports.get(packet.dport, 'Unknown')
            },
            'is_well_known_port': packet.sport in well_known_ports or packet.dport in well_known_ports
        }
    
    @staticmethod
    def analyze_packet(packet: IP, timestamp: datetime) -> Dict[str, Any]:
        analysis = {
            'timestamp': PacketAnalyzer.format_timestamp(timestamp),
            'ip_header': PacketAnalyzer.parse_ip_header(packet),
            'protocol': PacketAnalyzer.identify_protocol(packet),
            'size': PacketAnalyzer.calculate_packet_size(packet)
        }
        
        if TCP in packet:
            analysis['tcp'] = {
                'ports': PacketAnalyzer.analyze_tcp_ports(packet[TCP]),
                'flags': PacketAnalyzer.analyze_tcp_flags(packet[TCP])
            }
        
        return analysis
    
    @staticmethod
    def print_packet_analysis(analysis: Dict[str, Any]) -> None:
        """분석 결과 출력"""
        print(f"\n{Fore.CYAN}=== 패킷 분석 결과 ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}시간: {analysis['timestamp']['time']}{Style.RESET_ALL}")
        print(f"프로토콜: {analysis['protocol']}")
        print(f"출발지 IP: {analysis['ip_header']['src']}")
        print(f"목적지 IP: {analysis['ip_header']['dst']}")
        print(f"전체 크기: {analysis['size']['total_size']} bytes")
        print(f"TTL: {analysis['ip_header']['ttl']}") 
    
    @staticmethod
    def analyze_tcp_flags(packet: TCP) -> Dict[str, Any]:
        """TCP 플래그 분석"""
        # TCP 플래그 정의
        flags = {
            'F': ('FIN', 'Connection Finish'),
            'S': ('SYN', 'Synchronize'),
            'R': ('RST', 'Reset'),
            'P': ('PSH', 'Push'),
            'A': ('ACK', 'Acknowledgement'),
            'U': ('URG', 'Urgent'),
            'E': ('ECE', 'ECN Echo'),
            'C': ('CWR', 'Congestion Window Reduced')
        }
        
        # 활성화된 플래그 분석
        active_flags = []
        flag_str = packet.sprintf('%TCP.flags%')
        for flag_char, (name, desc) in flags.items():
            if flag_char in flag_str:
                active_flags.append({
                    'name': name,
                    'description': desc,
                    'value': True
                })
        
        # 연결 상태 분석
        connection_state = PacketAnalyzer._analyze_tcp_state(flag_str)
        
        return {
            'active_flags': active_flags,
            'connection_state': connection_state,
            'raw_flags': flag_str
        }
    
    @staticmethod
    def _analyze_tcp_state(flag_str: str) -> str:
        """TCP 연결 상태 분석"""
        if 'S' in flag_str and not 'A' in flag_str:
            return 'Connection Initiation'
        elif 'S' in flag_str and 'A' in flag_str:
            return 'Connection Establishment'
        elif 'F' in flag_str:
            return 'Connection Termination'
        elif 'R' in flag_str:
            return 'Connection Reset'
        elif 'A' in flag_str:
            return 'Data Transfer'
        else:
            return 'Unknown State'