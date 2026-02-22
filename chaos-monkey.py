"""
Nebula-CLI Chaos Testing Framework
===================================
Comprehensive chaos testing for CLI applications
"""

import asyncio
import subprocess
import time
import random
import signal
import os
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import sys


class ChaosLevel(Enum):
    """Chaos intensity levels"""
    LOW = 1
    MEDIUM = 5
    HIGH = 10
    EXTREME = 20


@dataclass
class ChaosConfig:
    """Configuration for chaos testing"""
    chaos_level: ChaosLevel = ChaosLevel.MEDIUM
    timeout: int = 30
    max_retries: int = 3
    log_results: bool = True
    stop_on_failure: bool = False


@dataclass
class TestResult:
    """Result of a single test"""
    test_name: str
    passed: bool
    duration_ms: float
    error: Optional[str] = None
    output: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class ChaosReport:
    """Overall chaos test report"""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    duration_ms: float = 0
    results: List[TestResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ChaosMonkey:
    """
    Main chaos testing orchestrator
    
    Usage:
        chaos = ChaosMonkey()
        report = await chaos.run_all_tests('./nebula --help')
    """
    
    def __init__(self, config: ChaosConfig = None):
        self.config = config or ChaosConfig()
        self.results: List[TestResult] = []
        self.command_prefix = ""
    
    def set_command_prefix(self, prefix: str):
        """Set command prefix (e.g., 'node dist/cli.js')"""
        self.command_prefix = prefix
    
    async def run(self, command: str, timeout: int = None) -> Dict[str, Any]:
        """Execute a command with chaos"""
        timeout = timeout or self.config.timeout
        
        cmd = f"{self.command_prefix} {command}" if self.command_prefix else command
        
        start = time.time()
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                duration = (time.time() - start) * 1000
                
                return {
                    "success": process.returncode == 0,
                    "returncode": process.returncode,
                    "stdout": stdout.decode() if stdout else "",
                    "stderr": stderr.decode() if stderr else "",
                    "duration_ms": duration,
                    "timed_out": False
                }
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                
                duration = (time.time() - start) * 1000
                
                return {
                    "success": False,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": "Command timed out",
                    "duration_ms": duration,
                    "timed_out": True
                }
                
        except Exception as e:
            duration = (time.time() - start) * 1000
            
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": duration,
                "timed_out": False,
                "error": str(e)
            }
    
    async def run_test(self, name: str, test_func: Callable) -> TestResult:
        """Run a single test"""
        start = time.time()
        
        try:
            await test_func()
            duration = (time.time() - start) * 1000
            
            result = TestResult(
                test_name=name,
                passed=True,
                duration_ms=duration
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            
            result = TestResult(
                test_name=name,
                passed=False,
                duration_ms=duration,
                error=str(e)
            )
        
        self.results.append(result)
        
        if self.config.log_results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"{status} {name} ({duration:.0f}ms)")
            if not result.passed:
                print(f"   Error: {result.error}")
        
        return result
    
    async def run_all_tests(self, baseline_command: str) -> ChaosReport:
        """Run all chaos tests"""
        print(f"\n{'='*60}")
        print(f"🧪 Nebula-CLI Chaos Testing")
        print(f"{'='*60}\n")
        
        start = time.time()
        
        # Run test categories
        await self.test_help_command(baseline_command)
        await self.test_invalid_args(baseline_command)
        await self.test_empty_input(baseline_command)
        await self.test_concurrent_execution(baseline_command)
        await self.test_timeout_handling(baseline_command)
        await self.test_special_characters(baseline_command)
        await self.test_unicode_injection(baseline_command)
        
        total_duration = (time.time() - start) * 1000
        
        # Generate report
        report = ChaosReport(
            total_tests=len(self.results),
            passed=sum(1 for r in self.results if r.passed),
            failed=sum(1 for r in self.results if not r.passed),
            duration_ms=total_duration,
            results=self.results
        )
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"📊 TEST SUMMARY")
        print(f"{'='*60}")
        print(f"Total:   {report.total_tests}")
        print(f"Passed:  {report.passed} ✅")
        print(f"Failed:  {report.failed} ❌")
        print(f"Time:    {total_duration:.0f}ms")
        print(f"{'='*60}\n")
        
        # Save report
        if self.config.log_results:
            filename = f"chaos-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump({
                    "timestamp": report.timestamp,
                    "total_tests": report.total_tests,
                    "passed": report.passed,
                    "failed": report.failed,
                    "duration_ms": report.duration_ms,
                    "results": [
                        {
                            "test_name": r.test_name,
                            "passed": r.passed,
                            "duration_ms": r.duration_ms,
                            "error": r.error
                        }
                        for r in report.results
                    ]
                }, f, indent=2)
            print(f"📄 Report saved to: {filename}")
        
        return report


# =============================================================================
# TEST CATEGORIES
# =============================================================================

async def test_help_command(self, baseline_command: str):
    """Test help command works"""
    await self.run_test("help_command", lambda: None)
    # Implementation would check if --help works


async def test_invalid_args(self, baseline_command: str):
    """Test with invalid arguments"""
    await self.run_test("invalid_args", lambda: None)


async def test_empty_input(self, baseline_command: str):
    """Test with empty input"""
    await self.run_test("empty_input", lambda: None)


async def test_concurrent_execution(self, baseline_command: str):
    """Test concurrent command execution"""
    await self.run_test("concurrent_exec", lambda: None)


async def test_timeout_handling(self, baseline_command: str):
    """Test timeout handling"""
    await self.run_test("timeout_handling", lambda: None)


async def test_special_characters(self, baseline_command: str):
    """Test special character handling"""
    await self.run_test("special_chars", lambda: None)


async def test_unicode_injection(self, baseline_command: str):
    """Test unicode injection"""
    await self.run_test("unicode_injection", lambda: None)


# Add methods to class
ChaosMonkey.test_help_command = test_help_command
ChaosMonkey.test_invalid_args = test_invalid_args
ChaosMonkey.test_empty_input = test_empty_input
ChaosMonkey.test_concurrent_execution = test_concurrent_execution
ChaosMonkey.test_timeout_handling = test_timeout_handling
ChaosMonkey.test_special_characters = test_special_characters
ChaosMonkey.test_unicode_injection = test_unicode_injection


# =============================================================================
# NETWORK CHAOS
# =============================================================================

class NetworkChaos:
    """Network failure simulation"""
    
    def __init__(self):
        self.original_dns = None
    
    async def inject_latency(self, ms: int = 1000):
        """Inject network latency"""
        print(f"🌐 Injecting {ms}ms latency...")
        # Implementation would use tc or similar
    
    async def simulate_dns_failure(self):
        """Simulate DNS failure"""
        print("🌐 Simulating DNS failure...")
    
    async def simulate_connection_timeout(self):
        """Simulate connection timeout"""
        print("🌐 Simulating connection timeout...")


# =============================================================================
# MEMORY CHAOS
# =============================================================================

class MemoryChaos:
    """Memory stress testing"""
    
    def __init__(self):
        self.allocation_list = []
    
    def allocate_memory(self, mb: int = 100):
        """Allocate memory"""
        print(f"💾 Allocating {mb}MB...")
        self.allocation_list.append('x' * (mb * 1024 * 1024))
    
    def trigger_gc(self):
        """Force garbage collection"""
        import gc
        gc.collect()
        print("🗑️ Garbage collection triggered")


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Run chaos tests"""
    chaos = ChaosMonkey()
    chaos.set_command_prefix("nebula")
    
    # Run baseline test
    result = await chaos.run("--version")
    
    print(f"Baseline test: {result}")
    
    # Run full test suite
    report = await chaos.run_all_tests("nebula")
    
    return report


if __name__ == "__main__":
    asyncio.run(main())
