"""HTTP/HTTPS protocol analyzer - detects errors, slow responses, and issues"""

from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class HTTPAnalyzer(BaseAnalyzer):
    """Analyzes HTTP/HTTPS traffic for issues"""

    def analyze(self) -> List[Dict[str, Any]]:
        """Analyze HTTP traffic"""
        issues = []

        # Check for HTTP error responses (4xx, 5xx)
        http_4xx_count = self.tshark.count_packets('http.response.code>=400 && http.response.code<500')
        if http_4xx_count > 0:
            severity = 'warning' if http_4xx_count > 10 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='HTTP 4xx Errors',
                description=f'Detected {http_4xx_count} HTTP 4xx client errors',
                count=http_4xx_count,
                details={
                    'filter': 'http.response.code>=400 && http.response.code<500',
                    'impact': 'Client-side errors (404, 403, etc.)'
                }
            ))

        http_5xx_count = self.tshark.count_packets('http.response.code>=500')
        if http_5xx_count > 0:
            severity = 'critical' if http_5xx_count > 5 else 'warning'
            issues.append(self.create_issue(
                severity=severity,
                category='HTTP 5xx Errors',
                description=f'Detected {http_5xx_count} HTTP 5xx server errors',
                count=http_5xx_count,
                details={
                    'filter': 'http.response.code>=500',
                    'impact': 'Server-side errors (500, 503, etc.)'
                }
            ))

        # Get specific error codes
        try:
            error_codes = self.tshark.get_field_values(
                'http.response.code',
                'http.response.code>=400'
            )
            if error_codes:
                from collections import Counter
                code_counts = Counter(error_codes).most_common()
                issues.append(self.create_issue(
                    severity='info',
                    category='HTTP Error Code Breakdown',
                    description='HTTP error code distribution',
                    count=len(error_codes),
                    details={
                        'filter': 'http.response.code>=400',
                        'error_codes': [{'code': code, 'count': count} for code, count in code_counts]
                    }
                ))
        except:
            pass

        # Check for HTTP requests
        http_requests = self.tshark.count_packets('http.request')
        http_responses = self.tshark.count_packets('http.response')

        if http_requests > 0:
            issues.append(self.create_issue(
                severity='info',
                category='HTTP Traffic Summary',
                description=f'{http_requests} HTTP requests, {http_responses} responses',
                count=http_requests,
                details={
                    'filter': 'http.request',
                    'requests': http_requests,
                    'responses': http_responses
                }
            ))

        # Get top requested URLs
        try:
            urls = self.tshark.get_field_values('http.request.uri', 'http.request')
            if urls:
                from collections import Counter
                top_urls = Counter(urls).most_common(5)
                issues.append(self.create_issue(
                    severity='info',
                    category='Top HTTP URLs',
                    description='Most requested URLs',
                    count=len(urls),
                    details={
                        'filter': 'http.request',
                        'top_urls': [{'url': url, 'count': count} for url, count in top_urls]
                    }
                ))
        except:
            pass

        return issues
