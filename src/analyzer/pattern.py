from typing import List, Dict
import statistics
from collections import defaultdict

class TrafficPatternAnalyzer:
    """트래픽 패턴 분석 클래스"""
    
    def analyze_patterns(self, packets: List[Dict]) -> Dict:
        """패킷 데이터의 패턴 분석"""
        if not packets:
            return {}
            
        time_patterns = self._analyze_time_patterns(packets)
        size_patterns = self._analyze_size_patterns(packets)
        
        return {
            'time_patterns': time_patterns,
            'size_patterns': size_patterns
        }
    
    def _analyze_time_patterns(self, packets: List[Dict]) -> Dict:
        """시간별 트래픽 패턴 분석"""
        packet_counts = defaultdict(int)
        
        for packet in packets:
            hour = packet['timestamp'].hour
            packet_counts[hour] += 1
        
        return {
            'traffic_trend': {
                'hours': list(range(24)),
                'packet_counts': [packet_counts[h] for h in range(24)]
            }
        }
    
    def _analyze_size_patterns(self, packets: List[Dict]) -> Dict:
        """패킷 크기 패턴 분석"""
        sizes = [packet['size'] for packet in packets]
        
        if not sizes:
            return {
                'average_size': 0,
                'median_size': 0,
                'std_dev': 0
            }
        
        return {
            'average_size': statistics.mean(sizes),
            'median_size': statistics.median(sizes),
            'std_dev': statistics.stdev(sizes) if len(sizes) > 1 else 0
        }