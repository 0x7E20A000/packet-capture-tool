from typing import List, Dict, Optional, Union, Any
from datetime import datetime
import json
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, 
    Paragraph, 
    Spacer, 
    Table, 
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.linecharts import HorizontalLineChart

from .statistics import PacketStatistics
from .pattern import TrafficPatternAnalyzer
from .anomaly import AnomalyDetector

class ReportGenerator:
    """패킷 분석 요약 보고서 생성 클래스"""
    
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
        self.statistics = PacketStatistics()
        self.pattern_analyzer = TrafficPatternAnalyzer()
        self.anomaly_detector = AnomalyDetector()
    
    def generate_report(self, packets: List[Dict], report_type: str = 'full') -> Dict:
        """요약 보고서 생성"""
        if not packets:
            return {'error': '분석할 패킷이 없습니다'}
            
        report = {
            'report_info': {
                'generated_at': datetime.now().isoformat(),
                'packet_count': len(packets),
                'time_range': {
                    'start': packets[0]['timestamp'].isoformat(),
                    'end': packets[-1]['timestamp'].isoformat()
                }
            }
        }
        
        # 보고서 유형에 따른 분석 수행
        if report_type in ['full', 'basic']:
            report['statistics'] = self.statistics.analyze_packets(packets)
            
        if report_type in ['full', 'pattern']:
            report['patterns'] = self.pattern_analyzer.analyze_patterns(packets)
            
        if report_type in ['full', 'anomaly']:
            report['anomalies'] = self.anomaly_detector.detect_anomalies(packets)
        
        # 주요 발견사항 요약
        report['key_findings'] = self._generate_key_findings(report)
        
        return report
    
    def save_report(self, report: Dict, filename: Optional[str] = None) -> str:
        """보고서 파일 저장"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_analysis_{timestamp}.json"
        
        filepath = self.report_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def _generate_key_findings(self, report: Dict) -> List[Dict]:
        """주요 발견사항 추출"""
        findings = []
        
        # 트래픽 볼륨 관련 발견사항
        if 'statistics' in report:
            stats = report['statistics']['basic_stats']
            if stats['packets_per_second'] > 1000:
                findings.append({
                    'type': 'high_traffic',
                    'description': f"높은 트래픽: {stats['packets_per_second']:.1f} pps",
                    'severity': 'warning'
                })
        
        # 패턴 관련 발견사항
        if 'patterns' in report:
            patterns = report['patterns']
            if patterns.get('periodic_patterns', {}).get('periodic'):
                findings.append({
                    'type': 'periodic_traffic',
                    'description': '주기적 트래픽 패턴 발견',
                    'severity': 'info'
                })
        
        # 이상 징후 관련 발견사항
        if 'anomalies' in report:
            anomalies = report['anomalies']
            if anomalies['summary']['severity_level'] != 'LOW':
                findings.append({
                    'type': 'security_alert',
                    'description': f"보안 경고: {anomalies['summary']['severity_level']} 수준의 이상 징후 발견",
                    'severity': 'critical' if anomalies['summary']['severity_level'] == 'HIGH' else 'warning'
                })
        
        return findings
    
    def generate_html_report(self, report: Dict, filename: Optional[str] = None) -> str:
        """HTML 형식의 보고서 생성"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_analysis_{timestamp}.html"
        
        filepath = self.report_dir / filename
        
        html_content = self._convert_to_html(report)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _convert_to_html(self, report: Dict) -> str:
        """보고서를 HTML 형식으로 변환"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>패킷 분석 보고서</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
                .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #666; }
                .critical { border-color: #ff4444; }
                .warning { border-color: #ffbb33; }
                .info { border-color: #33b5e5; }
            </style>
        </head>
        <body>
        """
        
        # 보고서 기본 정보
        html += f"""
        <h1>패킷 분석 보고서</h1>
        <div class="section">
            <h2>기본 정보</h2>
            <p>생성 시간: {report['report_info']['generated_at']}</p>
            <p>분석된 패킷 수: {report['report_info']['packet_count']}</p>
        </div>
        """
        
        # 주요 발견사항
        html += """
        <div class="section">
            <h2>주요 발견사항</h2>
        """
        for finding in report['key_findings']:
            html += f"""
            <div class="finding {finding['severity']}">
                <h3>{finding['type']}</h3>
                <p>{finding['description']}</p>
            </div>
            """
        
        # 나머지 섹션들 추가...
        html += """
        </body>
        </html>
        """
        
        return html

    def generate_pdf_report(self, report: Dict, filename: Optional[str] = None) -> str:
        """PDF 보고서 생성"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_analysis_{timestamp}.pdf"
        
        filepath = self.report_dir / filename
        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        styles = getSampleStyleSheet()
        
        # 커스텀 스타일 정의
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        ))
        
        # 보고서 구성요소
        elements = []
        
        # 제목 페이지
        elements.append(Paragraph("네트워크 트래픽 분석 보고서", styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"생성일시: {report['report_info']['generated_at']}", styles['Normal']))
        elements.append(Spacer(1, 30))
        
        # 주요 발견사항
        elements.append(Paragraph("주요 발견사항", styles['Heading2']))
        elements.append(Spacer(1, 12))
        for finding in report['key_findings']:
            elements.append(Paragraph(
                f"• {finding['description']}",
                styles['Normal']
            ))
        elements.append(Spacer(1, 20))
        
        # 통계 데이터 테이블
        if 'statistics' in report:
            elements.append(Paragraph("트래픽 통계", styles['Heading2']))
            stats = report['statistics']['basic_stats']
            data = [
                ['지표', '값'],
                ['총 패킷 수', f"{stats['total_packets']:,}"],
                ['초당 패킷', f"{stats['packets_per_second']:.2f} pps"],
                ['총 데이터량', f"{stats['total_bytes']:,} bytes"],
                ['평균 패킷 크기', f"{stats['average_packet_size']:.2f} bytes"]
            ]
            table = Table(data, colWidths=[200, 200])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))
        
        # 트래픽 패턴 그래프
        if 'patterns' in report:
            elements.append(Paragraph("트래픽 패턴 분석", styles['Heading2']))
            elements.append(Spacer(1, 12))
            
            # 라인 차트 생성
            drawing = Drawing(400, 200)
            lc = HorizontalLineChart()
            lc.x = 50
            lc.y = 50
            lc.height = 125
            lc.width = 300
            
            # 차트 데이터 설정
            patterns = report['patterns']
            if 'time_patterns' in patterns:
                data = patterns['time_patterns'].get('traffic_trend', {})
                lc.data = [data.get('packet_counts', [0])]
            
            drawing.add(lc)
            elements.append(drawing)
        
        # PDF 생성
        doc.build(elements)
        return str(filepath)
    
"""
패킷 분석 보고서 생성 모듈

사용 예시:
    # 보고서 생성기 초기화
    report_gen = ReportGenerator()
    
    # 패킷 데이터로부터 보고서 생성
    report = report_gen.generate_report(packets)
    
    # PDF 형식으로 저장
    pdf_path = report_gen.generate_pdf_report(report)
    print(f"PDF 보고서가 생성되었습니다: {pdf_path}")
"""    
    