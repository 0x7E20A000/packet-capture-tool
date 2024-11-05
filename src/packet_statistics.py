from typing import Dict, List
from datetime import datetime
import threading

class PacketCounter:
    """실시간 패킷 카운터"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.reset_counters()
    
    def reset_counters(self) -> None:
        """카운터 초기화"""
        self._counters = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'bytes_total': 0
        }
        
        self._size_distribution = {
            'small': 0,    # < 128 bytes
            'medium': 0,   # 128-1024 bytes
            'large': 0,    # > 1024 bytes
        }
        
        self._hourly_counts = {str(i): 0 for i in range(24)}
        self._last_update = datetime.now()
    
    def increment(self, protocol: str, size: int) -> None:
        """패킷 카운터 증가"""
        with self._lock:
            # 전체 카운터 증가
            self._counters['total'] += 1
            self._counters['bytes_total'] += size
            
            # 프로토콜별 카운터 증가
            if protocol.lower() in ['tcp', 'udp', 'icmp']:
                self._counters[protocol.lower()] += 1
            else:
                self._counters['other'] += 1
            
            # 크기별 분포 업데이트
            if size < 128:
                self._size_distribution['small'] += 1
            elif size < 1024:
                self._size_distribution['medium'] += 1
            else:
                self._size_distribution['large'] += 1
            
            # 시간별 통계 업데이트
            current_hour = str(datetime.now().hour)
            self._hourly_counts[current_hour] += 1
    
    def get_statistics(self) -> Dict:
        """현재 통계 반환"""
        with self._lock:
            return {
                'counters': self._counters.copy(),
                'size_distribution': self._size_distribution.copy(),
                'hourly_distribution': self._hourly_counts.copy(),
                'last_update': self._last_update.isoformat()
            } 