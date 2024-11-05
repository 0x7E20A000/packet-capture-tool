from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime
from typing import Dict, Optional, Any
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
    def analyze_packet(packet: IP, timestamp: datetime) -> Dict[str, Any]:
        """패킷 전체 분석"""
        return {
            'timestamp': PacketAnalyzer.format_timestamp(timestamp),
            'ip_header': PacketAnalyzer.parse_ip_header(packet),
            'protocol': PacketAnalyzer.identify_protocol(packet),
            'size': PacketAnalyzer.calculate_packet_size(packet)
        }
    
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