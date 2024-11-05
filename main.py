from src.packet_capture import PacketCapture
from src.cli import create_parser, validate_args
import sys
from colorama import Fore, Style

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not validate_args(args):
        sys.exit(0)
    
    capture = PacketCapture()
    try:
        capture.start_capture(
            interface=args.interface,
            packet_count=args.count
        )
        
        # 사용자 입력으로 캡처 제어
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