from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

class AnomalyDetector:
    """트래픽 이상 징후 탐지 클래스"""
    
    def __init__(self, 
                 threshold_std: float = 2.0,
                 min_samples: int = 30,
                 time_window: int = 60):
        self.threshold_std = threshold_std
        self.min_samples = min_samples
        self.time_window = time_window
        self.baseline = {}
        
    def detect_anomalies(self, packets: List[Dict]) -> Dict:
        """이상 징후 탐지 수행"""
        if len(packets) < self.min_samples:
            return {'error': '충분한 샘플 수가 없습니다'}
            
        # 기준 통계 계산
        self._calculate_baseline(packets)
        
        anomalies = {
            'volume_anomalies': self._detect_volume_anomalies(packets),
            'protocol_anomalies': self._detect_protocol_anomalies(packets),
            'behavioral_anomalies': self._detect_behavioral_anomalies(packets),
            'scan_attempts': self._detect_scan_attempts(packets)
        }
        
        return self._generate_anomaly_report(anomalies)
    
    def _calculate_baseline(self, packets: List[Dict]) -> None:
        """기준 통계 계산"""
        # 시간당 패킷 수 기준
        packets_per_window = self._get_packets_per_window(packets)
        self.baseline['mean_packets'] = statistics.mean(packets_per_window)
        self.baseline['std_packets'] = statistics.stdev(packets_per_window) if len(packets_per_window) > 1 else 0
        
        # 프로토콜 분포 기준
        protocol_counts = defaultdict(int)
        for packet in packets:
            protocol_counts[packet['protocol']] += 1
        total_packets = len(packets)
        self.baseline['protocol_dist'] = {
            proto: count/total_packets 
            for proto, count in protocol_counts.items()
        }
        
    def _detect_volume_anomalies(self, packets: List[Dict]) -> List[Dict]:
        """트래픽 양 기반 이상 징후 탐지"""
        anomalies = []
        packets_per_window = self._get_packets_per_window(packets)
        
        threshold = (self.baseline['mean_packets'] + 
                    self.threshold_std * self.baseline['std_packets'])
        
        for i, count in enumerate(packets_per_window):
            if count > threshold:
                anomalies.append({
                    'type': 'volume_spike',
                    'window_index': i,
                    'packet_count': count,
                    'threshold': threshold,
                    'severity': (count - threshold) / threshold
                })
        
        return anomalies
    
    def _detect_protocol_anomalies(self, packets: List[Dict]) -> List[Dict]:
        """프로토콜 기반 이상 징후 탐지"""
        anomalies = []
        current_dist = defaultdict(int)
        
        # 현재 프로토콜 분포 계산
        for packet in packets:
            current_dist[packet['protocol']] += 1
        total = sum(current_dist.values())
        
        for protocol, count in current_dist.items():
            expected = self.baseline['protocol_dist'].get(protocol, 0)
            current = count / total
            
            if abs(current - expected) > 0.1:  # 10% 이상 차이
                anomalies.append({
                    'type': 'protocol_anomaly',
                    'protocol': protocol,
                    'expected_ratio': expected,
                    'current_ratio': current,
                    'severity': abs(current - expected)
                })
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, packets: List[Dict]) -> List[Dict]:
        """행위 기반 이상 징후 탐지"""
        anomalies = []
        ip_behavior = defaultdict(lambda: {'ports': set(), 'protocols': set()})
        
        # IP별 행위 패턴 수집
        for packet in packets:
            src_ip = packet['source_ip']
            dst_ip = packet['dest_ip']
            
            for ip in [src_ip, dst_ip]:
                if 'tcp' in packet['analysis']:
                    ports = packet['analysis']['tcp']['ports']
                    ip_behavior[ip]['ports'].add(ports['src_port'])
                    ip_behavior[ip]['ports'].add(ports['dst_port'])
                ip_behavior[ip]['protocols'].add(packet['protocol'])
        
        # 이상 행위 탐지
        for ip, behavior in ip_behavior.items():
            if len(behavior['ports']) > 100:  # 포트 스캔 의심
                anomalies.append({
                    'type': 'port_scan_suspect',
                    'ip': ip,
                    'unique_ports': len(behavior['ports']),
                    'severity': len(behavior['ports']) / 100
                })
            
            if len(behavior['protocols']) > 5:  # 다중 프로토콜 사용
                anomalies.append({
                    'type': 'multi_protocol_anomaly',
                    'ip': ip,
                    'protocols': list(behavior['protocols']),
                    'severity': len(behavior['protocols']) / 5
                })
        
        return anomalies
    
    def _detect_scan_attempts(self, packets: List[Dict]) -> List[Dict]:
        """스캔 시도 탐지"""
        anomalies = []
        connection_attempts = defaultdict(set)
        
        for packet in packets:
            if packet['protocol'] == 'TCP':
                src_ip = packet['source_ip']
                dst_ip = packet['dest_ip']
                
                if 'tcp' in packet['analysis']:
                    flags = packet['analysis']['tcp'].get('flags', '')
                    if 'S' in flags:  # SYN 패킷
                        connection_attempts[src_ip].add(dst_ip)
        
        for src_ip, targets in connection_attempts.items():
            if len(targets) > 50:  # 다수의 대상 연결 시도
                anomalies.append({
                    'type': 'scan_attempt',
                    'source_ip': src_ip,
                    'target_count': len(targets),
                    'severity': len(targets) / 50
                })
        
        return anomalies
    
    def _get_packets_per_window(self, packets: List[Dict]) -> List[int]:
        """시간 윈도우별 패킷 수 계산"""
        windows = defaultdict(int)
        for packet in packets:
            window_idx = int(packet['timestamp'].timestamp() / self.time_window)
            windows[window_idx] += 1
        return list(windows.values())
    
    def _generate_anomaly_report(self, anomalies: Dict) -> Dict:
        """이상 징후 보고서 생성"""
        total_anomalies = sum(len(v) for v in anomalies.values())
        
        return {
            'summary': {
                'total_anomalies': total_anomalies,
                'severity_level': self._calculate_severity_level(anomalies),
                'timestamp': datetime.now().isoformat()
            },
            'details': anomalies
        }
    
    def _calculate_severity_level(self, anomalies: Dict) -> str:
        """전체 심각도 수준 계산"""
        if not any(anomalies.values()):
            return 'LOW'
            
        max_severity = max(
            max((a['severity'] for a in anom_list), default=0)
            for anom_list in anomalies.values()
        )
        
        if max_severity > 0.8:
            return 'HIGH'
        elif max_severity > 0.5:
            return 'MEDIUM'
        return 'LOW' 