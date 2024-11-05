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
            packet_count=args.count,
            duration=args.time
        )
        
        print("\n사용 가능한 명령어:")
        print("  s: 캡처 중지")
        print("  p: PDF 보고서 생성")
        print("  export csv: CSV로 내보내기")
        print("  export json: JSON으로 내보내기")
        print("  h: 도움말 표시")
        print("  q: 프로그램 종료")
        
        while capture.is_capturing:
            cmd = input().lower().strip()
            if cmd == 's':
                capture.stop_capture()
                break
            elif cmd == 'p':
                try:
                    pdf_path = capture.export_data(format='pdf')
                    print(f"{Fore.GREEN}PDF 보고서가 생성되었습니다: {pdf_path}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}PDF 생성 중 오류 발생: {e}{Style.RESET_ALL}")
            elif cmd.startswith('export'):
                try:
                    format = cmd.split()[1]
                    filepath = capture.export_data(format=format)
                    print(f"{Fore.GREEN}파일이 생성되었습니다: {filepath}{Style.RESET_ALL}")
                except (IndexError, ValueError) as e:
                    print(f"{Fore.RED}잘못된 내보내기 형식입니다. (csv/json/pdf){Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}내보내기 중 오류 발생: {e}{Style.RESET_ALL}")
            elif cmd == 'h':
                print("\n사용 가능한 명령어:")
                print("  s: 캡처 중지")
                print("  p: PDF 보고서 생성")
                print("  export csv: CSV로 내보내기")
                print("  export json: JSON으로 내보내기")
                print("  h: 도움말 표시")
                print("  q: 프로그램 종료")
            elif cmd == 'q':
                capture.stop_capture()
                break
    
    except KeyboardInterrupt:
        capture.stop_capture()
        print(f"\n{Fore.YELLOW}프로그램이 사용자에 의해 종료되었습니다.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}오류 발생: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 