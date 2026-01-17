import unittest
import asyncio
from modules.base import BaseModule
from modules.manager import ModuleManager
from modules.adapters import FunctionAdapter

class MockModule(BaseModule):
    def __init__(self, name="Mock"):
        super().__init__()
        self.name = name

    def run(self, target, **kwargs):
        return f"Scanned {target}"

class TestModuleManager(unittest.IsolatedAsyncioTestCase):
    async def test_module_registration(self):
        manager = ModuleManager()
        module = MockModule("TestMod")
        manager.register_module(module)
        
        self.assertIn("TestMod", manager.get_available_modules())
        self.assertEqual(manager.get_module("TestMod"), module)

    async def test_function_adapter(self):
        manager = ModuleManager()
        
        def simple_scan(target):
            return f"func {target}"
            
        adapter = FunctionAdapter("FuncMod", simple_scan)
        manager.register_module(adapter)
        
        result = await manager.run_module("FuncMod", "example.com")
        self.assertEqual(result, "func example.com")

    async def test_run_all(self):
        manager = ModuleManager()
        manager.register_module(MockModule("M1"))
        manager.register_module(MockModule("M2"))
        
        results = await manager.run_all("example.com")
        self.assertEqual(results["M1"], "Scanned example.com")
        self.assertEqual(results["M2"], "Scanned example.com")

if __name__ == "__main__":
    unittest.main()
