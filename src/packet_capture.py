from scapy.all import sniff, IP
from datetime import datetime, timedelta
import logging
from typing import Optional, Dict, List
from colorama import init, Fore, Style
import threading
import time
from .packet_analyzer import PacketAnalyzer
from .logger import PacketLogger
from .exporter import PacketExporter

# 컬러 출력 초기화
init()

class PacketCapture:
    """패킷 캡처 코어 클래스"""
    
    def __init__(self):
        self.packets: List[Dict] = []
        self.is_capturing: bool = False
        self.packet_count: int = 0
        self.max_packets: int = 0
        self.capture_thread: Optional[threading.Thread] = None
        self.start_time: Optional[datetime] = None
        self.duration: int = 0  # 캡처 지속 시간 (초)
        self.bytes_received: int = 0
        self.last_update_time: float = time.time()
        self.packets_per_second: float = 0
        self.bytes_per_second: float = 0
        self.analyzer = PacketAnalyzer()  # PacketAnalyzer 인스턴스 추가
        self.logger = PacketLogger()
        self.exporter = PacketExporter()
    
    def packet_callback(self, packet) -> None:
        """패킷 캡처 콜백"""
        if IP in packet:
            try:
                packet_size = len(packet)
                self.packet_count += 1
                self.bytes_received += packet_size
                
                current_time = datetime.now()
                analysis = self.analyzer.analyze_packet(packet, current_time)  # 인스턴스 메서드로 호출
                
                packet_info = {
                    'timestamp': current_time,
                    'source_ip': analysis['ip_header']['src'],
                    'dest_ip': analysis['ip_header']['dst'],
                    'protocol': analysis['protocol'],
                    'size': analysis['size']['total_size'],
                    'analysis': analysis
                }
                self.packets.append(packet_info)
                
                # 실시간 통계 업데이트
                self.update_statistics(packet_size)
                
                # 상태 표시줄 업데이트
                self.show_status()
                
                self.logger.log_packet(packet_info)
                
            except Exception as e:
                self.logger.logger.error(f"패킷 처리 중 오류 발생: {e}")
    
    def update_statistics(self, packet_size: int) -> None:
        """실시간 통계 업데이트"""
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        
        if time_diff >= 1.0:  # 1초마다 통계 업데이트
            self.packets_per_second = self.packet_count / time_diff
            self.bytes_per_second = self.bytes_received / time_diff
            self.last_update_time = current_time
            self.packet_count = 0
            self.bytes_received = 0
    
    def format_bytes(self, bytes: float) -> str:
        """바이트 단위 포맷팅"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f}{unit}"
            bytes /= 1024
        return f"{bytes:.1f}TB"
    
    def show_status(self) -> None:
        """실시간 상태 표시"""
        elapsed = self.get_elapsed_time()
        
        # 화면 지우기
        print("\033[H\033[J")
        
        # 기본 통계 정보
        print(f"{Fore.CYAN}=== 패킷 캡처 상태 ==={Style.RESET_ALL}")
        print(f"총 패킷 수: {self.packet_count:,}")
        print(f"초당 패킷: {self.packets_per_second:.1f} pps")
        print(f"대역폭: {self.format_bytes(self.bytes_per_second)}/s")
        
        # 최근 캡처된 패킷 정보
        print(f"\n{Fore.YELLOW}최근 캡처된 패킷:{Style.RESET_ALL}")
        for packet in self.packets[-10:]:  # 최근 10개 패킷만 표시
            try:
                analysis = packet['analysis']
                timestamp = packet['timestamp'].strftime('%H:%M:%S.%f')[:-3]
                
                # 기본 패킷 정보
                print(f"[{timestamp}] {packet['source_ip']} → {packet['dest_ip']} "
                      f"({packet['protocol']}, {self.format_bytes(packet['size'])})")
                
                # 프로토콜별 상세 정보
                if 'tcp' in analysis and 'ports' in analysis['tcp']:
                    ports = analysis['tcp']['ports']
                    flags = analysis['tcp'].get('flags', '')
                    print(f"  TCP - Port: {ports.get('src_port', '?')} → {ports.get('dst_port', '?')}"
                          f"{', Flags: ' + flags if flags else ''}")
                elif 'udp' in analysis and 'ports' in analysis['udp']:
                    ports = analysis['udp']['ports']
                    print(f"  UDP - Port: {ports.get('src_port', '?')} → {ports.get('dst_port', '?')}")
                elif 'icmp' in analysis:
                    icmp = analysis['icmp']
                    print(f"  ICMP - Type: {icmp.get('type', '?')}, Code: {icmp.get('code', '?')}")
                
            except Exception as e:
                self.logger.logger.debug(f"패킷 정보 표시 중 오류: {e}")
                continue
        
        print(f"\n{Fore.GREEN}Press 'Ctrl+C' to stop capturing{Style.RESET_ALL}")
    
    def start_capture(self, 
                     interface: Optional[str] = None, 
                     packet_count: int = 0,
                     duration: int = 0) -> None:
        """
        패킷 캡처 시작
        Args:
            interface: 캡처할 네트워크 인터페이스
            packet_count: 캡처할 최대 패킷 수 (0: 무제한)
            duration: 캡처 지속 시간 (초) (0: 무제한)
        """
        if self.is_capturing:
            print(f"{Fore.YELLOW}경고: 이미 캡처가 진행 중입니다.{Style.RESET_ALL}")
            return
        
        self.max_packets = packet_count
        self.duration = duration
        self.packet_count = 0
        self.start_time = datetime.now()
        self.is_capturing = True
        
        self.logger.start_logging()
        
        self.logger.info(
            f"캡처 시작 - 인터페이스: {interface or '기본'}, "
            f"최대 패킷 수: {packet_count or '무제한'}, "
            f"지속 시간: {duration or '무제한'}초"
        )
        
        # 시간 제한이 설정된 경우 타이머 스레드 시작
        if duration > 0:
            timer_thread = threading.Thread(target=self._duration_timer)
            timer_thread.daemon = True
            timer_thread.start()
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, packet_count)
        )
        self.capture_thread.start()
        
        print(f"{Fore.GREEN}패킷 캡처 시작... (종료: 's' 입력){Style.RESET_ALL}")
        if duration > 0:
            print(f"캡처 시간 제한: {duration}초")
    
    def stop_capture(self) -> None:
        """패킷 캡처 중지"""
        if not self.is_capturing:
            print(f"{Fore.YELLOW}경고: 실행 중인 캡처가 없습니다.{Style.RESET_ALL}")
            return
            
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join()
            print(f"\n{Fore.YELLOW}캡처가 중지되었습니다.{Style.RESET_ALL}")
            self.show_capture_summary()
        self.logger.stop_logging()
    
    def _capture_packets(self, interface: Optional[str], packet_count: int) -> None:
        """실제 패킷 캡처를 수행하는 내부 메서드"""
        try:
            sniff(
                iface=interface,
                prn=self.packet_callback,
                count=packet_count,
                store=False,
                stop_filter=lambda _: not self.is_capturing
            )
        except Exception as e:
            self.logger.logger.error(f"캡처 중 오류 발생: {e}")
            self.is_capturing = False
    
    def _duration_timer(self) -> None:
        """시간 제한 모니터링"""
        while self.is_capturing:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if self.duration > 0 and elapsed >= self.duration:
                print(f"\n{Fore.GREEN}설정된 시간({self.duration}초)이 경과했습니다.{Style.RESET_ALL}")
                self.stop_capture()
                break
            time.sleep(0.1)
    
    def get_elapsed_time(self) -> float:
        """캡처 시작부터 경과된 시간(초) 반환"""
        if not self.start_time:
            return 0.0
        return (datetime.now() - self.start_time).total_seconds()
    
    def show_capture_summary(self) -> None:
        """캡처 요약 정보 표시"""
        print(f"\n{Fore.CYAN}=== 캡처 요약 ==={Style.RESET_ALL}")
        print(f"��� 캡처된 패킷: {self.packet_count}")
    
    def export_data(self, format: str = 'csv', filters: Optional[Dict] = None) -> str:
        """캡처된 패킷 데이터 내보내기"""
        if format.lower() == 'csv':
            return self.exporter.export_csv(self.packets, filters=filters)
        elif format.lower() == 'json':
            return self.exporter.export_json(self.packets, filters=filters)
        else:
            raise ValueError(f"지원하지 않는 형식: {format}")
    