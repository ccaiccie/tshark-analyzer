"""Network layer analyzer - detects ICMP errors, ARP issues, and other network problems"""

from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class NetworkAnalyzer(BaseAnalyzer):
    """Analyzes network layer issues"""

    def analyze(self) -> List[Dict[str, Any]]:
        """Analyze network layer traffic"""
        issues = []

        # Check for ICMP destination unreachable
        icmp_unreach_count = self.tshark.count_packets('icmp.type==3')
        if icmp_unreach_count > 0:
            severity = 'warning' if icmp_unreach_count > 10 else 'info'
            issues.append(self.create_issue(
                severity=severity,
                category='ICMP Destination Unreachable',
                description=f'Detected {icmp_unreach_count} ICMP destination unreachable messages',
                count=icmp_unreach_count,
                details={
                    'filter': 'icmp.type==3',
                    'impact': 'Hosts or networks unreachable'
                }
            ))

        # Check for ICMP time exceeded (TTL)
        icmp_ttl_count = self.tshark.count_packets('icmp.type==11')
        if icmp_ttl_count > 0:
            issues.append(self.create_issue(
                severity='info',
                category='ICMP Time Exceeded',
                description=f'Detected {icmp_ttl_count} ICMP time exceeded messages',
                count=icmp_ttl_count,
                details={
                    'filter': 'icmp.type==11',
                    'impact': 'TTL expired, possible routing loops'
                }
            ))

        # Check for ARP duplicates
        try:
            arp_duplicates = self.tshark.count_packets('arp.duplicate-address-detected')
            if arp_duplicates > 0:
                issues.append(self.create_issue(
                    severity='warning',
                    category='ARP Duplicate Addresses',
                    description=f'Detected {arp_duplicates} duplicate IP address conflicts',
                    count=arp_duplicates,
                    details={
                        'filter': 'arp.duplicate-address-detected',
                        'impact': 'IP address conflicts on network'
                    }
                ))
        except:
            pass

        # Check for broadcast/multicast storms
        broadcast_count = self.tshark.count_packets('eth.dst==ff:ff:ff:ff:ff:ff')
        total_packets = self.tshark.get_basic_stats().get('total_packets', 1)

        if isinstance(total_packets, int) and total_packets > 0:
            broadcast_percent = (broadcast_count / total_packets) * 100
            if broadcast_percent > 10:
                issues.append(self.create_issue(
                    severity='warning',
                    category='High Broadcast Traffic',
                    description=f'{broadcast_percent:.2f}% broadcast traffic ({broadcast_count} packets)',
                    count=broadcast_count,
                    details={
                        'filter': 'eth.dst==ff:ff:ff:ff:ff:ff',
                        'percentage': round(broadcast_percent, 2),
                        'impact': 'Possible broadcast storm'
                    }
                ))

        # Get protocol distribution
        try:
            protocol_hierarchy = self.tshark.get_protocol_hierarchy()
            if protocol_hierarchy:
                issues.append(self.create_issue(
                    severity='info',
                    category='Protocol Distribution',
                    description='Traffic breakdown by protocol',
                    count=1,
                    details={
                        'filter': 'frame',  # Show all frames/packets
                        'hierarchy': protocol_hierarchy
                    }
                ))
        except:
            pass

        # Get top talkers
        try:
            conversations = self.tshark.get_conversations('ip')
            if conversations:
                sorted_convs = sorted(
                    conversations,
                    key=lambda x: int(x.get('bytes', '0').replace(',', '')),
                    reverse=True
                )[:5]

                # Create filter for top talkers (show packets involving these IPs)
                top_ips = set()
                total_frames = 0
                for conv in sorted_convs:
                    top_ips.add(conv['address_a'])
                    top_ips.add(conv['address_b'])
                    # Sum up frames from top conversations
                    try:
                        frames = int(conv.get('frames', '0').replace(',', ''))
                        total_frames += frames
                    except:
                        pass

                # Build OR filter: (ip.addr == IP1) or (ip.addr == IP2) or ...
                ip_filters = [f"ip.addr=={ip}" for ip in top_ips]
                combined_filter = " or ".join(ip_filters)

                # Count actual packets matching filter
                actual_packet_count = self.tshark.count_packets(combined_filter)

                issues.append(self.create_issue(
                    severity='info',
                    category='Top Bandwidth Consumers',
                    description=f'Top {len(sorted_convs)} conversations ({len(conversations)} total)',
                    count=actual_packet_count,
                    details={
                        'filter': combined_filter,
                        'top_conversations': sorted_convs
                    }
                ))
        except:
            pass

        return issues
