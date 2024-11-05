from typing import List, Dict
from collections import defaultdict
from datetime import datetime

class PacketStatistics:
    """패킷 기본 통계 분석 클래스"""
    
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.packet_sizes = []
        self.start_time: datetime = None
        self.end_time: datetime = None
    
    def analyze_packets(self, packets: List[Dict]) -> Dict:
        """패킷 데이터 기본 통계 분석"""
        if not packets:
            return {}
            
        # 시작/종료 시간
        self.start_time = packets[0]['timestamp']
        self.end_time = packets[-1]['timestamp']
        
        # 기본 통계 계산
        for packet in packets:
            self.total_packets += 1
            self.total_bytes += packet['size']
            self.protocol_counts[packet['protocol']] += 1
            self.packet_sizes.append(packet['size'])
        
        return self.generate_statistics()
    
    def generate_statistics(self) -> Dict:
        """통계 보고서 생성"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            'basic_stats': {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'duration_seconds': duration,
                'packets_per_second': self.total_packets / duration if duration > 0 else 0,
                'bytes_per_second': self.total_bytes / duration if duration > 0 else 0,
                'average_packet_size': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            },
            'protocol_distribution': dict(self.protocol_counts),
            'size_distribution': {
                'min': min(self.packet_sizes) if self.packet_sizes else 0,
                'max': max(self.packet_sizes) if self.packet_sizes else 0,
                'avg': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            },
            'time_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration
            }
        } 