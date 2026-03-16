"""Test method name vs function call differentiation."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.scanner import scan_content

def test_method_names_not_flagged():
    """Method names should not be flagged as dangerous."""
    
    test_cases = [
        # Method definitions
        ("editor.exec(command)", "JavaScript method call"),
        ("this.exec(cmd)", "Method call with this"),
        ("super.exec()", "Super method call"),
        ("obj.eval(expr)", "eval as method"),
        
        # Method declarations
        ("exec(cmd: string): void", "TypeScript method signature"),
        ("function exec(command) {", "Function declaration"),
        ("const exec = (cmd) => {", "Arrow function assignment"),
        ("exec: function(cmd) {", "Object method property"),
        
        # Class methods
        ("class Executor { exec() {} }", "Class method"),
        ("public exec(cmd: string) {", "Public method"),
        ("private eval(expr) {", "Private method"),
    ]
    
    for code, description in test_cases:
        findings = scan_content(code, "test.js")
        exec_eval_findings = [f for f in findings if 'exec' in f.rule or 'eval' in f.rule]
        assert len(exec_eval_findings) == 0, f"False positive for {description}: {code}"
    
def test_real_exec_eval_caught():
    """Real exec/eval calls should still be caught."""
    
    dangerous_cases = [
        ("exec(userInput)", "Direct exec call"),
        ("eval(code)", "Direct eval call"),
        ("os.system(cmd)", "os.system call"),
        ("subprocess.call(args)", "subprocess call"),
        # These should be caught
        ("exec('malicious')", "exec with string"),
        ("eval('alert(1)')", "eval with string"),
    ]
    
    for code, description in dangerous_cases:
        findings = scan_content(code, "test.js")
        exec_eval_findings = [f for f in findings if 'exec' in f.rule or 'eval' in f.rule]
        assert len(exec_eval_findings) > 0, f"Missed dangerous pattern {description}: {code}"

if __name__ == "__main__":
    test_method_names_not_flagged()
    test_real_exec_eval_caught()
    print("✓ All method detection tests pass")