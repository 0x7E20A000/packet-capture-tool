from typing import Dict, List, Any
from datetime import datetime
import threading
from collections import deque
from time import time

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

class ProtocolDistribution:
    """프로토콜 분포 분석"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.reset_distribution()
    
    def reset_distribution(self) -> None:
        """분포 데이터 초기화"""
        self._protocol_counts = {
            'tcp': {'count': 0, 'bytes': 0},
            'udp': {'count': 0, 'bytes': 0},
            'icmp': {'count': 0, 'bytes': 0},
            'other': {'count': 0, 'bytes': 0}
        }
        
        self._tcp_ports = {}
        self._udp_ports = {}
        self._total_packets = 0
        self._total_bytes = 0
    
    def update(self, protocol: str, size: int, src_port: int = None, 
              dst_port: int = None) -> None:
        """프로토콜 분포 업데이트"""
        with self._lock:
            protocol = protocol.lower()
            
            # 기본 카운트 업데이트
            if protocol in self._protocol_counts:
                self._protocol_counts[protocol]['count'] += 1
                self._protocol_counts[protocol]['bytes'] += size
            else:
                self._protocol_counts['other']['count'] += 1
                self._protocol_counts['other']['bytes'] += size
            
            # 포트 정보 업데이트
            if protocol == 'tcp' and (src_port or dst_port):
                self._update_port_stats(self._tcp_ports, src_port, dst_port)
            elif protocol == 'udp' and (src_port or dst_port):
                self._update_port_stats(self._udp_ports, src_port, dst_port)
            
            self._total_packets += 1
            self._total_bytes += size
    
    def _update_port_stats(self, port_dict: Dict, src_port: int, 
                          dst_port: int) -> None:
        """포트 통계 업데이트"""
        for port in [src_port, dst_port]:
            if port:
                port_dict[port] = port_dict.get(port, 0) + 1
    
    def get_distribution(self) -> Dict:
        """현재 분포 통계 반환"""
        with self._lock:
            stats = {
                'protocols': {
                    proto: {
                        'count': data['count'],
                        'bytes': data['bytes'],
                        'percentage': (data['count'] / self._total_packets * 100) 
                            if self._total_packets > 0 else 0
                    }
                    for proto, data in self._protocol_counts.items()
                },
                'total': {
                    'packets': self._total_packets,
                    'bytes': self._total_bytes
                },
                'top_ports': {
                    'tcp': self._get_top_ports(self._tcp_ports),
                    'udp': self._get_top_ports(self._udp_ports)
                }
            }
            return stats
    
    def _get_top_ports(self, port_dict: Dict, limit: int = 5) -> List[Dict]:
        """가장 많이 사용된 포트 반환"""
        sorted_ports = sorted(
            port_dict.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:limit]
        
        return [
            {'port': port, 'count': count} 
            for port, count in sorted_ports
        ]

class PacketRateMonitor:
    """초당 패킷 수 모니터링"""
    
    def __init__(self, window_size: int = 60):
        self._lock = threading.Lock()
        self.window_size = window_size  # 모니터링 윈도우 크기(초)
        self.reset_monitor()
    
    def reset_monitor(self) -> None:
        """모니터링 데이터 초기화"""
        self._packet_times = deque(maxlen=self.window_size)
        self._byte_counts = deque(maxlen=self.window_size)
        self._last_update = time()
        self._current_second = int(self._last_update)
        self._current_count = 0
        self._current_bytes = 0
    
    def update(self, packet_size: int) -> None:
        """패킷 발생 시 업데이트"""
        with self._lock:
            current_time = time()
            current_second = int(current_time)
            
            # 새로운 초가 시작되면 이전 데이터 저장
            if current_second > self._current_second:
                self._packet_times.append(self._current_count)
                self._byte_counts.append(self._current_bytes)
                self._current_count = 0
                self._current_bytes = 0
                self._current_second = current_second
            
            self._current_count += 1
            self._current_bytes += packet_size
            self._last_update = current_time
    
    def get_rates(self) -> Dict[str, Any]:
        """현재 패킷 레이트 통계 반환"""
        with self._lock:
            if not self._packet_times:
                return {
                    'current_pps': self._current_count,
                    'average_pps': self._current_count,
                    'peak_pps': self._current_count,
                    'current_bps': self._current_bytes * 8,
                    'average_bps': self._current_bytes * 8,
                    'peak_bps': self._current_bytes * 8
                }
            
            packet_rates = list(self._packet_times)
            byte_rates = list(self._byte_counts)
            
            return {
                'current_pps': self._current_count,
                'average_pps': sum(packet_rates) / len(packet_rates),
                'peak_pps': max(packet_rates + [self._current_count]),
                'current_bps': self._current_bytes * 8,
                'average_bps': (sum(byte_rates) / len(byte_rates)) * 8,
                'peak_bps': max(byte_rates + [self._current_bytes]) * 8
            }

class BandwidthMonitor:
    """대역폭 사용량 모니터링"""
    
    def __init__(self, interval: int = 1):
        self._lock = threading.Lock()
        self.interval = interval  # 측정 간격(초)
        self.reset_monitor()
    
    def reset_monitor(self) -> None:
        """모니터링 데이터 초기화"""
        self._bandwidth_data = {
            'current': {'bytes': 0, 'timestamp': time()},
            'intervals': deque(maxlen=60),  # 1분간의 데이터 유지
            'total': {
                'bytes': 0,
                'start_time': time(),
                'peak_bandwidth': 0
            }
        }
    
    def update(self, packet_size: int) -> None:
        """패킷 수신시 대역폭 업데이트"""
        with self._lock:
            current_time = time()
            self._bandwidth_data['current']['bytes'] += packet_size
            self._bandwidth_data['total']['bytes'] += packet_size
            
            # 측정 간격이 지나면 통계 업데이트
            if current_time - self._bandwidth_data['current']['timestamp'] >= self.interval:
                bandwidth = (self._bandwidth_data['current']['bytes'] * 8) / self.interval  # bits per second
                
                self._bandwidth_data['intervals'].append({
                    'timestamp': current_time,
                    'bandwidth': bandwidth
                })
                
                # 최대 대역폭 업데이트
                if bandwidth > self._bandwidth_data['total']['peak_bandwidth']:
                    self._bandwidth_data['total']['peak_bandwidth'] = bandwidth
                
                # 현재 구간 초기화
                self._bandwidth_data['current'] = {
                    'bytes': 0,
                    'timestamp': current_time
                }
    
    def get_statistics(self) -> Dict[str, Any]:
        """대역폭 통계 반환"""
        with self._lock:
            current_time = time()
            current_interval = current_time - self._bandwidth_data['current']['timestamp']
            
            if current_interval > 0:
                current_bandwidth = (self._bandwidth_data['current']['bytes'] * 8) / current_interval
            else:
                current_bandwidth = 0
            
            intervals = list(self._bandwidth_data['intervals'])
            total_time = current_time - self._bandwidth_data['total']['start_time']
            
            return {
                'current': {
                    'bps': current_bandwidth,
                    'mbps': current_bandwidth / 1_000_000
                },
                'average': {
                    'bps': (self._bandwidth_data['total']['bytes'] * 8) / total_time if total_time > 0 else 0,
                    'mbps': ((self._bandwidth_data['total']['bytes'] * 8) / total_time) / 1_000_000 if total_time > 0 else 0
                },
                'peak': {
                    'bps': self._bandwidth_data['total']['peak_bandwidth'],
                    'mbps': self._bandwidth_data['total']['peak_bandwidth'] / 1_000_000
                },
                'total_bytes': self._bandwidth_data['total']['bytes'],
                'duration': total_time
            }