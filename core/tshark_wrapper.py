"""
Wrapper around tshark command-line tool
Provides methods to extract various information from PCAP files
"""

import subprocess
import json
import re
from typing import List, Dict, Any, Optional


class TsharkWrapper:
    """Wrapper for tshark commands"""

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self._verify_tshark()

    def _verify_tshark(self):
        """Verify tshark is installed"""
        try:
            subprocess.run(
                ['tshark', '--version'],
                capture_output=True,
                check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(
                "tshark not found. Please install wireshark/tshark: "
                "sudo apt-get install tshark"
            )

    def _run_tshark(self, args: List[str]) -> str:
        """Run tshark command and return output"""
        cmd = ['tshark', '-r', self.pcap_file] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark error: {e.stderr}")

    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the PCAP file"""
        # Get capinfos output
        try:
            result = subprocess.run(
                ['capinfos', '-m', '-c', '-u', '-a', '-e', self.pcap_file],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout

            stats = {}
            for line in output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    stats[key.strip()] = value.strip()

            return {
                'total_packets': int(stats.get('Number of packets', '0').replace(',', '')),
                'duration': stats.get('Capture duration', 'Unknown'),
                'start_time': stats.get('First packet time', 'Unknown'),
                'end_time': stats.get('Last packet time', 'Unknown'),
                'file_size': stats.get('File size', 'Unknown')
            }
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to basic tshark
            return {'total_packets': 'Unknown', 'duration': 'Unknown'}

    def get_expert_info(self) -> List[Dict[str, Any]]:
        """Get expert info from tshark"""
        output = self._run_tshark(['-q', '-z', 'expert'])

        expert_items = []
        severity_pattern = re.compile(r'(\w+)\s+\((\d+)\)')

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('=') or 'expert' in line.lower():
                continue

            match = severity_pattern.search(line)
            if match:
                severity = match.group(1)
                count = int(match.group(2))
                message = line.split(':', 1)[-1].strip() if ':' in line else line

                expert_items.append({
                    'severity': severity.lower(),
                    'count': count,
                    'message': message
                })

        return expert_items

    def get_protocol_hierarchy(self) -> str:
        """Get protocol hierarchy statistics"""
        return self._run_tshark(['-q', '-z', 'io,phs'])

    def get_conversations(self, proto: str = 'tcp') -> List[Dict[str, Any]]:
        """Get conversation statistics for a protocol"""
        output = self._run_tshark(['-q', '-z', f'conv,{proto}'])

        conversations = []
        in_data = False

        for line in output.split('\n'):
            line = line.strip()

            if '<->' in line and not line.startswith('='):
                in_data = True
                parts = line.split()
                if len(parts) >= 7:
                    conversations.append({
                        'address_a': parts[0],
                        'address_b': parts[2],
                        'frames': parts[3] if len(parts) > 3 else '0',
                        'bytes': parts[4] if len(parts) > 4 else '0'
                    })

        return conversations

    def get_packets_json(self, display_filter: Optional[str] = None,
                        fields: Optional[List[str]] = None,
                        limit: int = 0) -> List[Dict[str, Any]]:
        """Get packets in JSON format with optional filter and fields"""
        args = []

        if display_filter:
            args.extend(['-Y', display_filter])

        if fields:
            args.append('-T')
            args.append('json')
            args.append('-e')
            args.append('frame.number')
            for field in fields:
                args.extend(['-e', field])
        else:
            args.extend(['-T', 'json'])

        if limit > 0:
            args.extend(['-c', str(limit)])

        output = self._run_tshark(args)

        try:
            return json.loads(output) if output.strip() else []
        except json.JSONDecodeError:
            return []

    def get_field_values(self, field: str, display_filter: Optional[str] = None) -> List[str]:
        """Extract specific field values from packets"""
        args = ['-T', 'fields', '-e', field]

        if display_filter:
            args.extend(['-Y', display_filter])

        output = self._run_tshark(args)
        return [line.strip() for line in output.split('\n') if line.strip()]

    def count_packets(self, display_filter: str) -> int:
        """Count packets matching a display filter"""
        try:
            output = self._run_tshark(['-Y', display_filter, '-T', 'fields', '-e', 'frame.number'])
            return len([line for line in output.split('\n') if line.strip()])
        except:
            return 0

    def get_packet_details(self, display_filter: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get detailed packet information for packets matching a filter"""
        args = ['-Y', display_filter]
        args.extend(['-T', 'fields'])
        args.extend(['-e', 'frame.number'])
        args.extend(['-e', 'frame.time'])
        args.extend(['-e', 'ip.src'])
        args.extend(['-e', 'ip.dst'])
        args.extend(['-e', 'ipv6.src'])
        args.extend(['-e', 'ipv6.dst'])
        args.extend(['-e', 'tcp.srcport'])
        args.extend(['-e', 'tcp.dstport'])
        args.extend(['-e', 'udp.srcport'])
        args.extend(['-e', 'udp.dstport'])
        args.extend(['-e', 'frame.protocols'])
        args.extend(['-e', 'frame.len'])
        args.extend(['-e', '_ws.col.Info'])
        args.extend(['-E', 'header=y'])
        args.extend(['-E', 'separator=|'])
        args.extend(['-E', 'occurrence=f'])  # First occurrence only

        # NOTE: Don't use -c flag here! It limits packets READ, not packets RETURNED
        # We'll limit the results after tshark filters them

        try:
            output = self._run_tshark(args)
        except Exception as e:
            # If extraction fails, return empty list
            print(f"DEBUG: tshark error: {e}")
            return []

        packets = []
        lines = output.split('\n')

        print(f"DEBUG: Got {len(lines)} lines from tshark")
        if len(lines) > 0:
            print(f"DEBUG: First line (header): {lines[0]}")
        if len(lines) > 1:
            print(f"DEBUG: Second line (first data): {lines[1]}")

        if len(lines) < 2:
            print(f"DEBUG: Not enough lines returned")
            return packets

        # Skip header
        parsed_count = 0
        skipped_count = 0
        for line in lines[1:]:
            if not line.strip():
                continue

            fields = line.split('|')
            if len(fields) < 4:  # At minimum need frame number and timestamp
                skipped_count += 1
                print(f"DEBUG: Skipped line with {len(fields)} fields: {line[:100]}")
                continue

            parsed_count += 1

            # Safely extract fields with defaults
            frame_number = fields[0] if len(fields) > 0 else ''
            timestamp = fields[1] if len(fields) > 1 else ''
            src_ip = fields[2] if len(fields) > 2 else ''
            dst_ip = fields[3] if len(fields) > 3 else ''
            src_ipv6 = fields[4] if len(fields) > 4 else ''
            dst_ipv6 = fields[5] if len(fields) > 5 else ''
            tcp_src_port = fields[6] if len(fields) > 6 else ''
            tcp_dst_port = fields[7] if len(fields) > 7 else ''
            udp_src_port = fields[8] if len(fields) > 8 else ''
            udp_dst_port = fields[9] if len(fields) > 9 else ''
            protocols = fields[10] if len(fields) > 10 else ''
            length = fields[11] if len(fields) > 11 else ''
            info = fields[12] if len(fields) > 12 else ''

            # Use IPv6 if IPv4 is not present
            if not src_ip and src_ipv6:
                src_ip = src_ipv6
            if not dst_ip and dst_ipv6:
                dst_ip = dst_ipv6

            # Determine port based on protocol
            src_port = tcp_src_port if tcp_src_port else udp_src_port
            dst_port = tcp_dst_port if tcp_dst_port else udp_dst_port

            packets.append({
                'frame_number': frame_number,
                'timestamp': timestamp,
                'src_ip': src_ip if src_ip else 'N/A',
                'dst_ip': dst_ip if dst_ip else 'N/A',
                'src_port': src_port if src_port else '-',
                'dst_port': dst_port if dst_port else '-',
                'protocols': protocols,
                'length': length,
                'info': info
            })

        print(f"DEBUG: Parsed {parsed_count} packets, skipped {skipped_count} lines")

        # Apply limit after filtering (not before)
        if limit > 0 and len(packets) > limit:
            print(f"DEBUG: Limiting from {len(packets)} to {limit} packets")
            packets = packets[:limit]

        print(f"DEBUG: Returning {len(packets)} packets")
        return packets

    def get_frame_numbers(self, display_filter: str, limit: int = 0) -> List[int]:
        """Get frame numbers for packets matching a filter"""
        args = ['-Y', display_filter, '-T', 'fields', '-e', 'frame.number']

        if limit > 0:
            args.extend(['-c', str(limit)])

        output = self._run_tshark(args)
        frame_numbers = []

        for line in output.split('\n'):
            line = line.strip()
            if line and line.isdigit():
                frame_numbers.append(int(line))

        return frame_numbers
