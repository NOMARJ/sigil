// Regression test for eval() context detection fix
// Safe eval() usage should NOT be flagged as dangerous

export function testDryRunContexts() {
  // These eval() references should NOT be flagged - they're in safe contexts
  
  // 1. eval in regex pattern - safe context
  const evalRegex = /eval\(/g;
  const dynamicCodeRegex = /(?:eval|exec|Function)\s*\(/;
  
  // 2. eval in string literals - safe context  
  const description = "This function checks for eval() patterns in code";
  const warning = 'Detected eval() usage - potential security risk';
  const helpText = `
    The following patterns are dangerous:
    - eval("malicious code")
    - new Function("return " + userInput)
  `;
  
  // 3. eval in comments - safe context
  // This comment mentions eval() but shouldn't be flagged
  /* 
   * Another comment about eval() detection
   * Multiple lines with eval() references
   */
  
  return {
    patterns: [evalRegex, dynamicCodeRegex],
    messages: [description, warning, helpText]
  };
}

// This real eval() SHOULD be flagged as dangerous
export function dangerousExample() {
  if (process.env.NODE_ENV === 'development') {
    eval('console.log("This should be flagged")');
  }
  
  // This Function constructor SHOULD also be flagged  
  return new Function('x', 'y', 'return x + y');
}