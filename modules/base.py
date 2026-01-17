from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class BaseModule(ABC):
    """
    Abstract base class for all WebAnalyzer modules.
    Enforces a standard interface for execution and metadata.
    """
    
    def __init__(self):
        self.name: str = "BaseModule"
        self.description: str = "Base module description"
        self.dependencies: list = []

    @abstractmethod
    def run(self, target: str, **kwargs) -> Any:
        """
        Execute the module's main logic.
        
        Args:
            target (str): The domain or IP to scan.
            **kwargs: Additional arguments specific to the module.
            
        Returns:
            Any: The results of the scan (usually a dict or list).
        """
        pass
