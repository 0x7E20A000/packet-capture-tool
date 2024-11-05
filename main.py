from src.packet_capture import PacketCapture
from src.cli import create_parser, validate_args
import sys

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
    except KeyboardInterrupt:
        print("\n프로그램이 사용자에 의해 종료되었습니다.")
    except Exception as e:
        print(f"오류 발생: {e}")

if __name__ == "__main__":
    main() 