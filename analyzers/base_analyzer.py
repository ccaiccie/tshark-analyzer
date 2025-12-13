"""Base class for all analyzers"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.tshark_wrapper import TsharkWrapper


class BaseAnalyzer(ABC):
    """Base analyzer class"""

    def __init__(self, tshark: TsharkWrapper):
        self.tshark = tshark
        self.name = self.__class__.__name__

    @abstractmethod
    def analyze(self) -> List[Dict[str, Any]]:
        """Analyze PCAP and return list of issues"""
        pass

    def create_issue(self, severity: str, category: str,
                    description: str, count: int = 1,
                    details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Helper to create standardized issue dictionary"""
        return {
            'severity': severity,
            'category': category,
            'description': description,
            'count': count,
            'details': details or {},
            'analyzer': self.name
        }
