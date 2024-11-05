import argparse
import textwrap
from colorama import init, Fore, Style
from .network_interface import NetworkInterfaceManager

# 컬러 출력 초기화
init()

def create_parser() -> argparse.ArgumentParser:
    """CLI 인자 파서 생성"""
    parser = argparse.ArgumentParser(
        description='Network Packet Capture Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            사용 예시:
              %(prog)s -i eth0            # eth0 인터페이스에서 패킷 캡처
              %(prog)s -i eth0 -c 100     # 100개 패킷만 캡처
              %(prog)s -l                 # 사용 가능한 인터페이스 목록 표시
              
            단축키:
              Ctrl+C: 캡처 중지
        ''')
    )
    
    parser.add_argument('-i', '--interface',
                      help='캡처할 네트워크 인터페이스')
    parser.add_argument('-c', '--count', type=int, default=0,
                      help='캡처할 패킷 수 (기본값: 무제한)')
    parser.add_argument('-l', '--list-interfaces', action='store_true',
                      help='사용 가능한 네트워크 인터페이스 목록 표시')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='상세 출력 모드')
    
    return parser

def validate_interface(interface: str) -> bool:
    """인터페이스 유효성 검증"""
    if not interface:
        return True  # 기본 인터페이스 사용
    
    if not NetworkInterfaceManager.check_interface(interface):
        print(f"{Fore.RED}오류: '{interface}' 인터페이스를 찾을 수 없습니다.{Style.RESET_ALL}")
        print("\n사용 가능한 인터페이스 목록:")
        NetworkInterfaceManager.print_interface_list()
        return False
    
    details = NetworkInterfaceManager.get_interface_details(interface)
    if not details.get('is_up'):
        print(f"{Fore.YELLOW}경고: '{interface}' 인터페이스가 비활성 상태입니다.{Style.RESET_ALL}")
    
    return True