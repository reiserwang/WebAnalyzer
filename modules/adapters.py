from typing import Callable, Any, Dict
from .base import BaseModule

class FunctionAdapter(BaseModule):
    """
    Adapter for modules that are implemented as a simple function.
    """
    def __init__(self, name: str, func: Callable, description: str = ""):
        super().__init__()
        self.name = name
        self.func = func
        self.description = description

    def run(self, target: str, **kwargs) -> Any:
        # Some legacy functions take 'domain' instead of 'target', or just positionally.
        # We try to inspect or just pass generic arguments.
        # Most of the codebase seems to follow func(domain, ...).
        return self.func(target, **kwargs)

class ClassAdapter(BaseModule):
    """
    Adapter for modules that are implemented as a class with a run/scan method.
    """
    def __init__(self, name: str, cls_instance: Any, method_name: str = "run", description: str = ""):
        super().__init__()
        self.name = name
        self.instance = cls_instance
        self.method_name = method_name
        self.description = description

    def run(self, target: str, **kwargs) -> Any:
        method = getattr(self.instance, self.method_name)
        # Assuming the method signature usually starts with domain/target or takes it as arg
        # We will try passing target as first arg if possible, or kwargs.
        # This might need specific tuning per module, but for now we try simple invocation.
        return method(target, **kwargs)

class AsyncFunctionAdapter(BaseModule):
    """
    Adapter for modules that are implemented as an async function.
    """
    def __init__(self, name: str, func: Callable, description: str = ""):
        super().__init__()
        self.name = name
        self.func = func
        self.description = description

    async def run(self, target: str, **kwargs) -> Any:
        return await self.func(target, **kwargs)
