import logging
import asyncio
from typing import Dict, List, Any, Optional, Type
from .base import BaseModule

logger = logging.getLogger("ModuleManager")

class ModuleManager:
    """
    Central manager for registering, retrieving, and executing modules.
    """
    
    def __init__(self):
        self._modules: Dict[str, BaseModule] = {}

    def register_module(self, module: BaseModule):
        """
        Register a module instance.
        """
        if not isinstance(module, BaseModule):
            raise TypeError(f"Module must inherit from BaseModule, got {type(module)}")
        
        if module.name in self._modules:
            logger.warning(f"Module '{module.name}' is being overwritten.")
            
        self._modules[module.name] = module
        logger.debug(f"Registered module: {module.name}")

    def get_module(self, name: str) -> Optional[BaseModule]:
        """
        Retrieve a module by name.
        """
        return self._modules.get(name)

    def get_available_modules(self) -> List[str]:
        """
        Return a list of registered module names.
        """
        return list(self._modules.keys())

    async def run_module(self, name: str, target: str, **kwargs) -> Any:
        """
        Execute a specific module by name.
        Handles both sync and async execution transparently.
        """
        module = self.get_module(name)
        if not module:
            raise ValueError(f"Module '{name}' not found.")

        try:
            # Check if the run method is a coroutine
            if asyncio.iscoroutinefunction(module.run):
                return await module.run(target, **kwargs)
            else:
                # Run synchronous modules in a thread to verify blocking the event loop
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, lambda: module.run(target, **kwargs))
        except Exception as e:
            logger.error(f"Error executing module '{name}': {e}")
            return {"error": str(e)}

    async def run_all(self, target: str, module_names: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """
        Run multiple modules concurrently.
        
        Args:
            target (str): The scan target.
            module_names (List[str], optional): specific modules to run. If None, run all.
            
        Returns:
            Dict[str, Any]: Combined results keyed by module name.
        """
        results = {}
        to_run = module_names if module_names else self.get_available_modules()
        
        # Filter out invalid module names
        valid_modules = [name for name in to_run if name in self._modules]
        
        # Create tasks for all valid modules
        tasks = [self.run_module(name, target, **kwargs) for name in valid_modules]
        
        # Run concurrently
        module_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for name, res in zip(valid_modules, module_results):
            if isinstance(res, Exception):
                results[name] = {"error": str(res)}
            else:
                results[name] = res
                
        return results
