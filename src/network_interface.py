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
    def print_interface_list() -> None:
        """사용 가능한 인터페이스 목록 출력"""
        interfaces = get_if_list()
        
        print(f"\n{Fore.CYAN}=== 사용 가능한 네트워크 인터페이스 ==={Style.RESET_ALL}")
        for iface in interfaces:
            details = NetworkInterfaceManager.get_interface_details(iface)
            status = f"{Fore.GREEN}활성" if details.get('is_up') else f"{Fore.RED}비활성"
            
            print(f"\n{Fore.YELLOW}인터페이스: {iface}{Style.RESET_ALL}")
            print(f"  상태: {status}{Style.RESET_ALL}")
            print(f"  IP 주소: {details.get('ip_address', 'N/A')}")
            print(f"  MAC 주소: {details.get('mac_address', 'N/A')}") 