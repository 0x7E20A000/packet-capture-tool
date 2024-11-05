import logging
import os
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path
import asyncio
from logging.handlers import RotatingFileHandler
from queue import Queue
from threading import Thread

class PacketLogger:
    """패킷 로깅 관리 클래스"""
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_file_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5,
                 buffer_size: int = 1000):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.current_log_file: Optional[str] = None
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.buffer: Queue = Queue(maxsize=buffer_size)
        self.is_running = False
        self.writer_thread: Optional[Thread] = None
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """로거 초기화"""
        logger = logging.getLogger("packet_logger")
        logger.setLevel(logging.INFO)
        
        # 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def _create_rotating_handler(self) -> None:
        """로그 로테이션 핸들러 생성"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"packet_capture_{timestamp}.log"
        
        handler = RotatingFileHandler(
            log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.current_log_file = log_file
    
    def _write_buffer(self) -> None:
        """버퍼의 패킷을 비동기로 파일에 쓰기"""
        while self.is_running or not self.buffer.empty():
            try:
                if not self.buffer.empty():
                    packet_info = self.buffer.get()
                    self.logger.info(
                        f"패킷: {packet_info['source_ip']} → {packet_info['dest_ip']} "
                        f"({packet_info['protocol']}, {packet_info['size']} bytes)"
                    )
                    self.buffer.task_done()
                else:
                    asyncio.sleep(0.1)
            except Exception as e:
                self.logger.error(f"패킷 쓰기 중 오류 발생: {e}")
    
    def start_logging(self) -> None:
        """로깅 시작"""
        self._create_rotating_handler()
        self.is_running = True
        self.writer_thread = Thread(target=self._write_buffer)
        self.writer_thread.daemon = True
        self.writer_thread.start()
        self.logger.info("패킷 캡처 시작")
    
    def stop_logging(self) -> None:
        """로깅 종료"""
        if self.current_log_file:
            self.is_running = False
            if self.writer_thread:
                self.writer_thread.join()
            self.logger.info("패킷 캡처 종료")
            for handler in self.logger.handlers[:]:
                if isinstance(handler, (logging.FileHandler, RotatingFileHandler)):
                    handler.close()
                    self.logger.removeHandler(handler)
    
    def log_packet(self, packet_info: dict) -> None:
        """패킷 정보를 버퍼에 추가"""
        if not self.current_log_file:
            self.start_logging()
        
        try:
            self.buffer.put(packet_info, block=False)
        except Exception as e:
            self.logger.error(f"패킷 버퍼링 중 오류 발생: {e}")