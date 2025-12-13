"""DNS protocol analyzer - detects DNS failures, slow queries, and anomalies"""

from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class DNSAnalyzer(BaseAnalyzer):
    """Analyzes DNS traffic for issues"""

    def analyze(self) -> List[Dict[str, Any]]:
        """Analyze DNS traffic"""
        issues = []

        # Check for DNS failures (NXDOMAIN, SERVFAIL, etc.)
        nxdomain_count = self.tshark.count_packets('dns.flags.rcode==3')
        if nxdomain_count > 0:
            severity = 'warning' if nxdomain_count > 10 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='DNS NXDOMAIN',
                description=f'Detected {nxdomain_count} DNS NXDOMAIN responses',
                count=nxdomain_count,
                details={
                    'filter': 'dns.flags.rcode==3',
                    'impact': 'Domain names not found',
                    'rcode': 'NXDOMAIN'
                }
            ))

        # Check for SERVFAIL
        servfail_count = self.tshark.count_packets('dns.flags.rcode==2')
        if servfail_count > 0:
            issues.append(self.create_issue(
                severity='warning',
                category='DNS SERVFAIL',
                description=f'Detected {servfail_count} DNS SERVFAIL responses',
                count=servfail_count,
                details={
                    'filter': 'dns.flags.rcode==2',
                    'impact': 'DNS server failures',
                    'rcode': 'SERVFAIL'
                }
            ))

        # Check for unanswered DNS queries
        dns_queries = self.tshark.count_packets('dns.flags.response==0')
        dns_responses = self.tshark.count_packets('dns.flags.response==1')

        if dns_queries > 0 and dns_responses < dns_queries:
            unanswered = dns_queries - dns_responses
            if unanswered > 0:
                severity = 'critical' if unanswered > 20 else 'warning'
                issues.append(self.create_issue(
                    severity=severity,
                    category='DNS Timeouts',
                    description=f'{unanswered} DNS queries without responses',
                    count=unanswered,
                    details={
                        'filter': 'dns.flags.response==0',
                        'queries': dns_queries,
                        'responses': dns_responses,
                        'impact': 'DNS resolution failures or timeouts'
                    }
                ))

        # Check for high number of DNS queries (potential DNS tunneling or DDoS)
        if dns_queries > 1000:
            issues.append(self.create_issue(
                severity='info',
                category='High DNS Query Volume',
                description=f'Detected {dns_queries} DNS queries',
                count=dns_queries,
                details={
                    'filter': 'dns.flags.response==0',
                    'impact': 'Unusually high DNS traffic - check for DNS tunneling or issues'
                }
            ))

        # Get most queried domains
        try:
            query_names = self.tshark.get_field_values('dns.qry.name', 'dns.flags.response==0')
            if query_names:
                from collections import Counter
                top_queries = Counter(query_names).most_common(5)
                issues.append(self.create_issue(
                    severity='info',
                    category='Top DNS Queries',
                    description=f'Top queried domains',
                    count=len(query_names),
                    details={
                        'filter': 'dns.flags.response==0',
                        'top_domains': [{'domain': domain, 'count': count} for domain, count in top_queries]
                    }
                ))
        except:
            pass

        return issues
