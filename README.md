# 네트워크 패킷 분석 도구 (Network Packet Analysis Tool)

실시간 네트워크 트래픽을 캡처하고 분석하는 파이썬 기반 도구입니다.

## 주요 기능

- 실시간 패킷 캡처 및 분석
- TCP/UDP/ICMP 프로토콜 분석
- 트래픽 패턴 및 이상 징후 탐지
- JSON/CSV/PDF 형식의 보고서 생성
- 실시간 모니터링 및 통계
- TCP 세션 추적

## 모듈별 설명

### 코어 모듈
- `packet_capture.py`: 패킷 캡처 핵심 기능
  - 실시간 패킷 캡처
  - 패킷 필터링
  - 캡처 세션 관리

- `packet_analyzer.py`: 패킷 분석 엔진
  - IP/TCP/UDP/ICMP 헤더 분석
  - 프로토콜 식별
  - 포트 분석
  - 패킷 크기 계산

### 분석 모듈 (src/analyzer/)
- `anomaly.py`: 이상 징후 탐지
  - 트래픽 패턴 이상 감지
  - 보안 위협 탐지
  - 심각도 평가

- `pattern.py`: 트래픽 패턴 분석
  - 주기적 패턴 식별
  - 트래픽 추세 분석
  - 행동 패턴 분석

- `report.py`: 보고서 생성
  - JSON/HTML/PDF 형식 지원
  - 통계 데이터 시각화
  - 주요 발견사항 요약

- `statistics.py`: 통계 분석
  - 트래픽 볼륨 분석
  - 프로토콜 분포
  - 시계열 분석

### 유틸리티 모듈
- `cli.py`: 명령줄 인터페이스
  - 인자 파싱
  - 인터페이스 검증
  - 사용자 입력 처리

- `logger.py`: 로깅 시스템
  - 패킷 로그 기록
  - 로그 파일 관리
  - 로그 순환

- `network_interface.py`: 네트워크 인터페이스 관리
  - 인터페이스 목록 조회
  - 상태 모니터링
  - 상세 정보 조회

## 설치 방법

1. 저장소 클론
```bash
git clone https://github.com/yourusername/packet-capture-tool.git
cd packet-capture-tool
```

2. 가상환경 생성 및 활성화
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows
```

3. 의존성 설치
```bash
pip install -r requirements.txt
```

## 사용 방법

기본 사용:
```bash
python main.py -i eth0
```

옵션:
- `-i, --interface`: 캡처할 네트워크 인터페이스
- `-c, --count`: 캡처할 패킷 수 제한
- `-l, --list-interfaces`: 사용 가능한 인터페이스 목록
- `-v, --verbose`: 상세 출력 모드

## 보고서 생성 예시

```python
from src.analyzer.report import ReportGenerator

# 보고서 생성기 초기화
report_gen = ReportGenerator()

# 패킷 데이터로부터 보고서 생성
report = report_gen.generate_report(packets)

# PDF 형식으로 저장
pdf_path = report_gen.generate_pdf_report(report)
print(f"PDF 보고서가 생성되었습니다: {pdf_path}")
```
```
# 인터페이스 목록 확인
python main.py -l

# macOS에서 기본 인터페이스(en0)로 캡처
python main.py -i en0 -c 100 -v

# TCP 트래픽 테스트
curl http://example.com &
python main.py -i en0 -c 10

# UDP 트래픽 테스트
dig @8.8.8.8 google.com &
python main.py -i en0 -c 5

# ICMP 트래픽 테스트
ping -c 4 8.8.8.8 &
python main.py -i en0 -c 5

# 로그 확인
tail -f logs/packet_capture_*.log

# 캡처 시간 제한 테스트
python main.py -i en0 -c 100 -t 30
```
