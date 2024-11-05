import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

class PacketExporter:
    """패킷 데이터 내보내기 클래스"""
    
    def __init__(self, export_dir: str = "exports"):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)
    
    def _prepare_packet_data(self, packets: List[Dict], filters: Optional[Dict] = None) -> List[Dict]:
        """패킷 데이터 필터링 및 전처리"""
        filtered_packets = []
        
        for packet in packets:
            if filters:
                # 프로토콜 필터
                if 'protocol' in filters and packet['protocol'] != filters['protocol']:
                    continue
                    
                # IP 필터
                if 'ip' in filters:
                    if packet['source_ip'] != filters['ip'] and packet['dest_ip'] != filters['ip']:
                        continue
                        
                # 포트 필터
                if 'port' in filters:
                    if 'tcp' in packet['analysis']:
                        ports = packet['analysis']['tcp']['ports']
                        if ports['src_port'] != filters['port'] and ports['dst_port'] != filters['port']:
                            continue
                    elif 'udp' in packet['analysis']:
                        ports = packet['analysis']['udp']['ports']
                        if ports['src_port'] != filters['port'] and ports['dst_port'] != filters['port']:
                            continue
            
            filtered_packets.append(packet)
        
        return filtered_packets
    
    def export_csv(self, packets: List[Dict], filename: Optional[str] = None, filters: Optional[Dict] = None) -> str:
        """CSV 형식으로 내보내기"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_capture_{timestamp}.csv"
        
        filepath = self.export_dir / filename
        filtered_packets = self._prepare_packet_data(packets, filters)
        
        try:
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'source_ip', 'dest_ip', 'protocol', 'size', 
                            'src_port', 'dst_port', 'flags', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for packet in filtered_packets:
                    row = {
                        'timestamp': packet['timestamp'],
                        'source_ip': packet['source_ip'],
                        'dest_ip': packet['dest_ip'],
                        'protocol': packet['protocol'],
                        'size': packet['size'],
                        'src_port': self._get_port(packet, 'src'),
                        'dst_port': self._get_port(packet, 'dst'),
                        'flags': self._get_tcp_flags(packet),
                        'details': json.dumps(packet['analysis'])
                    }
                    writer.writerow(row)
            
            return str(filepath)
        except Exception as e:
            raise Exception(f"CSV 내보내기 중 오류 발생: {e}")
    
    def export_json(self, packets: List[Dict], filename: Optional[str] = None, filters: Optional[Dict] = None) -> str:
        """JSON 형식으로 내보내기"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_capture_{timestamp}.json"
        
        filepath = self.export_dir / filename
        filtered_packets = self._prepare_packet_data(packets, filters)
        
        try:
            with open(filepath, 'w') as jsonfile:
                json.dump({
                    'capture_info': {
                        'timestamp': datetime.now().isoformat(),
                        'packet_count': len(filtered_packets)
                    },
                    'packets': filtered_packets
                }, jsonfile, indent=2)
            
            return str(filepath)
        except Exception as e:
            raise Exception(f"JSON 내보내기 중 오류 발생: {e}")
    
    def _get_port(self, packet: Dict, direction: str) -> Optional[int]:
        """패킷에서 포트 정보 추출"""
        if 'tcp' in packet['analysis']:
            return packet['analysis']['tcp']['ports'][f'{direction}_port']
        elif 'udp' in packet['analysis']:
            return packet['analysis']['udp']['ports'][f'{direction}_port']
        return None
    
    def _get_tcp_flags(self, packet: Dict) -> Optional[str]:
        """TCP 플래그 정보 추출"""
        if 'tcp' in packet['analysis']:
            return packet['analysis']['tcp'].get('flags', '')
        return None 