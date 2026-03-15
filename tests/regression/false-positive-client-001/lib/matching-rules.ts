// Regression test for RegExp.exec false positive fix
// This file should NOT be flagged as dangerous shell execution

export class RuleEngine {
  private rules: RegExp[] = [];
  
  /**
   * Add a new matching rule to the engine
   * @param pattern - Regular expression pattern as string
   */
  addRule(pattern: string): void {
    this.rules.push(new RegExp(pattern));
  }
  
  /**
   * Execute all rules against input text
   * This should NOT trigger "dangerous shell execution" because it's RegExp.exec
   * @param text - Input text to match against
   * @returns Array of matched strings
   */
  executeRules(text: string): string[] {
    const matches: string[] = [];
    
    for (const rule of this.rules) {
      let match;
      // This RegExp.exec should be recognized as safe, not dangerous shell exec
      while ((match = rule.exec(text)) !== null) {
        matches.push(match[0]);
        
        // Prevent infinite loops on global regexes
        if (!rule.global) break;
      }
    }
    
    return matches;
  }
  
  /**
   * Test if any rule matches the input
   * @param text - Input text to test
   * @returns True if any rule matches
   */
  hasMatch(text: string): boolean {
    return this.rules.some(rule => rule.exec(text) !== null);
  }
}