from src.packet_capture import PacketCapture
from src.cli import create_parser, validate_interface
import sys
from colorama import Fore, Style

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if args.list_interfaces:
        from src.network_interface import NetworkInterfaceManager
        NetworkInterfaceManager.print_interface_list()
        sys.exit(0)
    
    if not validate_interface(args.interface):
        sys.exit(0)
    
    capture = PacketCapture()
    try:
        capture.start_capture(
            interface=args.interface,
            packet_count=args.count
        )
        
        print(f"\n{Fore.CYAN}명령어 도움말 보기: 'h' 입력{Style.RESET_ALL}")
        
        while True:
            cmd = input().lower()
            if cmd == 's':
                capture.stop_capture()
                break
            elif cmd == 'h':
                print("\n사용 가능한 명령어:")
                print("  s: 캡처 중지")
                print("  h: 도움말 표시")
    
    except KeyboardInterrupt:
        capture.stop_capture()
        print(f"\n{Fore.YELLOW}프로그램이 사용자에 의해 종료되었습니다.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}오류 발생: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 