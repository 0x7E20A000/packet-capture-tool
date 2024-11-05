from scapy.all import sniff, IP
from datetime import datetime
import logging
from typing import Optional, Dict, List
from colorama import init, Fore, Style

# 컬러 출력 초기화
init()

class PacketCapture:
    """패킷 캡처 코어 클래스"""
    
    def __init__(self):
        self.packets: List[Dict] = []
        self.is_capturing: bool = False
        self.packet_count: int = 0
        self.setup_logging()
    
    def setup_logging(self) -> None:
        """로깅 설정"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def packet_callback(self, packet) -> None:
        """패킷 캡처 콜백"""
        if IP in packet:
            try:
                self.packet_count += 1
                packet_info = {
                    'timestamp': datetime.now(),
                    'source_ip': packet[IP].src,
                    'dest_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'size': len(packet),
                }
                self.packets.append(packet_info)
                
                # 컬러 출력으로 실시간 패킷 정보 표시
                print(f"{Fore.GREEN}[{packet_info['timestamp']}] "
                      f"{Fore.BLUE}{packet_info['source_ip']} "
                      f"{Fore.WHITE}-> "
                      f"{Fore.YELLOW}{packet_info['dest_ip']} "
                      f"{Fore.CYAN}({packet_info['protocol']}) "
                      f"{Fore.MAGENTA}{packet_info['size']} bytes"
                      f"{Style.RESET_ALL}")
                
            except Exception as e:
                self.logger.error(f"패킷 처리 중 오류 발생: {e}")
    
    def start_capture(self, 
                     interface: Optional[str] = None, 
                     packet_count: int = 0) -> None:
        """패킷 캡처 시작"""
        self.is_capturing = True
        self.logger.info(
            f"캡처 시작 - 인터페이스: {interface or '기본'}"
        )
        
        try:
            print(f"{Fore.GREEN}패킷 캡처 시작... (종료: Ctrl+C){Style.RESET_ALL}")
            sniff(
                iface=interface,
                prn=self.packet_callback,
                count=packet_count,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}사용자에 의해 캡처 중지{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}캡처 중 오류 발생: {e}{Style.RESET_ALL}")
        finally:
            self.is_capturing = False
            self.show_capture_summary()
    
    def show_capture_summary(self) -> None:
        """캡처 요약 정보 표시"""
        print(f"\n{Fore.CYAN}=== 캡처 요약 ==={Style.RESET_ALL}")
        print(f"총 캡처된 패킷: {self.packet_count}")