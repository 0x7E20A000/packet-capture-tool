from scapy.arch import get_if_list, get_if_addr, get_if_hwaddr
import platform
import psutil
from typing import Dict, List
from colorama import Fore, Style

class NetworkInterfaceManager:
    """네트워크 인터페이스 관리 클래스"""
    
    @staticmethod
    def get_interfaces() -> List[str]:
        """사용 가능한 네트워크 인터페이스 목록 반환"""
        return get_if_list()
    
    @staticmethod
    def get_interface_details(interface: str) -> Dict:
        """특정 인터페이스의 상세 정보 반환"""
        try:
            return {
                'ip_address': get_if_addr(interface),
                'mac_address': get_if_hwaddr(interface),
                'is_up': NetworkInterfaceManager._is_interface_up(interface)
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _is_interface_up(interface: str) -> bool:
        """인터페이스 활성화 상태 확인"""
        try:
            stats = psutil.net_if_stats()
            return stats.get(interface, None) is not None and stats[interface].isup
        except:
            return False
    
    @staticmethod
    def check_interface(interface: str) -> bool:
        """인터페이스 유효성 검사"""
        return interface in get_if_list()
    
    @staticmethod
    def print_interface_list(page_size: int = 5) -> None:
        """사용 가능한 네트워크 인터페이스 목록 출력 (페이징)"""
        interfaces = get_if_list()
        total_pages = (len(interfaces) + page_size - 1) // page_size
        current_page = 1

        while True:
            print("\033[H\033[J")  # 화면 지우기
            print(f"{Fore.CYAN}=== 네트워크 인터페이스 목록 ({current_page}/{total_pages}) ==={Style.RESET_ALL}")
            print(f"{'인터페이스':^15} | {'상태':^8} | {'MAC 주소':^17} | {'IPv4 주소':^15}")
            print("-" * 65)

            start_idx = (current_page - 1) * page_size
            end_idx = min(start_idx + page_size, len(interfaces))

            for iface in interfaces[start_idx:end_idx]:
                details = NetworkInterfaceManager.get_interface_details(iface)
                status = f"{Fore.GREEN}활성{Style.RESET_ALL}" if details['is_up'] else f"{Fore.RED}비활성{Style.RESET_ALL}"
                print(f"{iface:15} | {status:^8} | {details['mac_address']:^17} | {details['ip_address']:^15}")

            print("\n[n]다음 [p]이전 [q]종료")
            choice = input("선택: ").lower()

            if choice == 'q':
                break
            elif choice == 'n' and current_page < total_pages:
                current_page += 1
            elif choice == 'p' and current_page > 1:
                current_page -= 1