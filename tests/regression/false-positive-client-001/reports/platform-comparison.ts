// Regression test for String.fromCharCode and safe domains fixes

export class PlatformComparison {
  
  /**
   * Generate Excel column names (A, B, C, ..., Z, AA, AB, ...)
   * This String.fromCharCode usage should NOT be flagged as obfuscation
   * @param index - Column index (0-based)
   * @returns Column name string
   */
  getExcelColumn(index: number): string {
    let columnName = '';
    while (index >= 0) {
      // Single character generation - should be recognized as benign
      columnName = String.fromCharCode(65 + (index % 26)) + columnName;
      index = Math.floor(index / 26) - 1;
    }
    return columnName;
  }
  
  /**
   * Convert number to letter (1=A, 2=B, etc.)
   * Single character fromCharCode - should NOT trigger obfuscation warning
   * @param num - Number to convert (1-26)
   * @returns Single letter
   */
  numberToLetter(num: number): string {
    if (num < 1 || num > 26) {
      throw new Error('Number must be between 1 and 26');
    }
    // Simple single character generation - benign usage
    return String.fromCharCode(64 + num);
  }
  
  /**
   * Generate alphabet array
   * @returns Array of letters A-Z
   */
  generateAlphabet(): string[] {
    const letters: string[] = [];
    for (let i = 0; i < 26; i++) {
      // Single character generation in loop - should be benign
      letters.push(String.fromCharCode(65 + i));
    }
    return letters;
  }
  
  /**
   * API calls to legitimate AI services - should NOT be flagged as suspicious
   * These domains are in the SAFE_DOMAINS allowlist
   */
  async fetchModelComparisons() {
    const results = [];
    
    try {
      // OpenAI API - safe domain, should not be flagged
      const openaiResponse = await fetch('https://api.openai.com/v1/models', {
        headers: { 'Authorization': 'Bearer ' + process.env.OPENAI_KEY }
      });
      results.push({
        provider: 'OpenAI',
        models: await openaiResponse.json()
      });
      
      // Anthropic API - safe domain, should not be flagged  
      const anthropicResponse = await fetch('https://api.anthropic.com/v1/models', {
        headers: { 'X-API-Key': process.env.ANTHROPIC_KEY }
      });
      results.push({
        provider: 'Anthropic', 
        models: await anthropicResponse.json()
      });
      
      // HuggingFace API - safe domain, should not be flagged
      const hfResponse = await fetch('https://api.huggingface.co/models');
      results.push({
        provider: 'HuggingFace',
        models: await hfResponse.json()
      });
      
    } catch (error) {
      console.error('Error fetching model data:', error);
    }
    
    return results;
  }
  
  /**
   * This function contains obfuscated content that SHOULD be flagged
   * Multiple character codes used for obfuscation - should trigger warning
   */
  private getSuspiciousMessage(): string {
    // This String.fromCharCode chain should be flagged as obfuscation
    return String.fromCharCode(72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100);
  }
}