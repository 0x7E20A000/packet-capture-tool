from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np
from scipy import stats

class TrafficPatternAnalyzer:
    """트래픽 패턴 분석 클래스"""
    
    def __init__(self, time_window: int = 60):  # 기본 시간 윈도우: 60초
        self.time_window = time_window
        self.time_series = defaultdict(list)
        self.patterns = {}
    
    def analyze_patterns(self, packets: List[Dict]) -> Dict:
        """트래픽 패턴 분석 수행"""
        if not packets:
            return {}
            
        # 시계열 데이터 생성
        self._create_time_series(packets)
        
        # 패턴 분석
        return {
            'time_patterns': self._analyze_time_patterns(),
            'protocol_patterns': self._analyze_protocol_patterns(),
            'size_patterns': self._analyze_size_patterns(),
            'periodic_patterns': self._detect_periodic_patterns()
        }
    
    def _create_time_series(self, packets: List[Dict]) -> None:
        """시계열 데이터 생성"""
        current_window = None
        window_packets = []
        
        for packet in packets:
            timestamp = packet['timestamp']
            if not current_window:
                current_window = timestamp
            
            # 새로운 시간 윈도우 확인
            if (timestamp - current_window).total_seconds() >= self.time_window:
                # 이전 윈도우 데이터 저장
                self._process_window(current_window, window_packets)
                # 새 윈도우 시작
                current_window = timestamp
                window_packets = []
            
            window_packets.append(packet)
    
    def _process_window(self, window_time: datetime, packets: List[Dict]) -> None:
        """시간 윈도우 데이터 처리"""
        self.time_series['packet_count'].append(len(packets))
        self.time_series['bytes'].append(sum(p['size'] for p in packets))
        self.time_series['protocols'].append(
            defaultdict(int, [(p['protocol'], 1) for p in packets])
        )
    
    def _analyze_time_patterns(self) -> Dict:
        """시간별 트래픽 패턴 분석"""
        return {
            'traffic_trend': {
                'mean_packets': np.mean(self.time_series['packet_count']),
                'std_packets': np.std(self.time_series['packet_count']),
                'peak_time_windows': self._find_peak_times()
            }
        }
    
    def _analyze_protocol_patterns(self) -> Dict:
        """프로토콜 패턴 분석"""
        protocol_trends = defaultdict(list)
        for window in self.time_series['protocols']:
            for protocol, count in window.items():
                protocol_trends[protocol].append(count)
        
        return {
            'protocol_trends': {
                protocol: {
                    'mean': np.mean(counts),
                    'std': np.std(counts),
                    'trend': 'increasing' if self._is_increasing(counts) else 'decreasing'
                }
                for protocol, counts in protocol_trends.items()
            }
        }
    
    def _analyze_size_patterns(self) -> Dict:
        """패킷 크기 패턴 분석"""
        bytes_series = self.time_series['bytes']
        return {
            'size_trend': {
                'mean_bytes': np.mean(bytes_series),
                'std_bytes': np.std(bytes_series),
                'trend': 'increasing' if self._is_increasing(bytes_series) else 'decreasing'
            }
        }
    
    def _detect_periodic_patterns(self) -> Dict:
        """주기적 패턴 탐지"""
        packet_counts = self.time_series['packet_count']
        if len(packet_counts) < 3:
            return {'periodic': False}
            
        # 자기상관 분석
        autocorr = stats.pearsonr(packet_counts[:-1], packet_counts[1:])[0]
        
        return {
            'periodic': autocorr > 0.7,
            'correlation': autocorr,
            'period_length': self._estimate_period(packet_counts)
        }
    
    def _is_increasing(self, values: List[float]) -> bool:
        """증가 추세 확인"""
        if len(values) < 2:
            return False
        slope, _ = np.polyfit(range(len(values)), values, 1)
        return slope > 0
    
    def _find_peak_times(self) -> List[datetime]:
        """피크 트래픽 시간대 탐지"""
        mean = np.mean(self.time_series['packet_count'])
        std = np.std(self.time_series['packet_count'])
        threshold = mean + 2 * std
        
        return [i for i, count in enumerate(self.time_series['packet_count'])
                if count > threshold]
    
    def _estimate_period(self, values: List[float]) -> Optional[int]:
        """주기 길이 추정"""
        if len(values) < 4:
            return None
            
        # FFT를 사용한 주기 추정
        fft = np.fft.fft(values)
        freqs = np.fft.fftfreq(len(values))
        peak_freq = freqs[np.argmax(np.abs(fft))]
        
        if peak_freq == 0:
            return None
            
        return int(1 / abs(peak_freq)) 