from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from scapy.all import TCP
import threading

@dataclass
class TCPSession:
    """TCP 세션 정보를 저장하는 데이터 클래스"""
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_time: datetime
    last_update: datetime
    state: str
    packets_count: int = 0
    bytes_transferred: int = 0
    is_active: bool = True

class TCPSessionTracker:
    """TCP 세션 추적 관리 클래스"""
    
    def __init__(self):
        self.sessions: Dict[str, TCPSession] = {}
        self._lock = threading.Lock()
    
    def _generate_session_id(self, src_ip: str, dst_ip: str, 
                           src_port: int, dst_port: int) -> str:
        """세션 ID 생성"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def track_packet(self, packet: TCP, src_ip: str, dst_ip: str) -> Dict:
        """패킷을 추적하고 세션 정보 업데이트"""
        with self._lock:
            session_id = self._generate_session_id(
                src_ip, dst_ip, packet.sport, packet.dport
            )
            reverse_session_id = self._generate_session_id(
                dst_ip, src_ip, packet.dport, packet.sport
            )
            
            # 기존 세션 확인
            session = self.sessions.get(session_id) or self.sessions.get(reverse_session_id)
            
            current_time = datetime.now()
            if not session:
                # 새 세션 생성
                session = TCPSession(
                    session_id=session_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=packet.sport,
                    dst_port=packet.dport,
                    start_time=current_time,
                    last_update=current_time,
                    state=self._determine_initial_state(packet),
                )
                self.sessions[session_id] = session
            else:
                # 기존 세션 업데이트
                session.last_update = current_time
                session.state = self._determine_state(packet, session.state)
                session.packets_count += 1
                session.bytes_transferred += len(packet)
            
            return self._create_session_info(session)
    
    def _determine_initial_state(self, packet: TCP) -> str:
        """초기 세션 상태 결정"""
        flags = packet.sprintf('%TCP.flags%')
        if 'S' in flags:
            return 'SYN_SENT'
        return 'UNKNOWN'
    
    def _determine_state(self, packet: TCP, current_state: str) -> str:
        """TCP 상태 전이 결정"""
        flags = packet.sprintf('%TCP.flags%')
        
        state_transitions = {
            'SYN_SENT': {
                'SA': 'ESTABLISHED',
                'R': 'CLOSED'
            },
            'ESTABLISHED': {
                'F': 'FIN_WAIT',
                'R': 'CLOSED'
            },
            'FIN_WAIT': {
                'F': 'CLOSED',
                'A': 'CLOSED'
            }
        }
        
        if current_state in state_transitions and flags in state_transitions[current_state]:
            return state_transitions[current_state][flags]
        return current_state
    
    def _create_session_info(self, session: TCPSession) -> Dict:
        """세션 정보를 딕셔너리로 변환"""
        return {
            'session_id': session.session_id,
            'source': {
                'ip': session.src_ip,
                'port': session.src_port
            },
            'destination': {
                'ip': session.dst_ip,
                'port': session.dst_port
            },
            'timing': {
                'start_time': session.start_time.isoformat(),
                'last_update': session.last_update.isoformat(),
                'duration': (session.last_update - session.start_time).total_seconds()
            },
            'state': session.state,
            'statistics': {
                'packets': session.packets_count,
                'bytes': session.bytes_transferred
            },
            'is_active': session.is_active
        } 