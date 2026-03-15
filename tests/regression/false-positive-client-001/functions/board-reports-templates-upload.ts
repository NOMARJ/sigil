// Regression test for RegExp.exec vs shell execution detection
// Board reporting functions with RegExp operations

export interface TemplateConfig {
  name: string;
  pattern: RegExp;
  processor: (match: RegExpExecArray) => string;
}

export class BoardReportProcessor {
  private templates: TemplateConfig[] = [];
  
  /**
   * Register a new template configuration
   * @param config - Template configuration with regex pattern
   */
  registerTemplate(config: TemplateConfig): void {
    this.templates.push(config);
  }
  
  /**
   * Process uploaded report content against registered templates
   * This uses RegExp.exec which should NOT be flagged as shell execution
   * @param content - Raw report content
   * @returns Processed template matches
   */
  processUploadedContent(content: string): Array<{template: string, matches: string[]}> {
    const results: Array<{template: string, matches: string[]}> = [];
    
    for (const template of this.templates) {
      const matches: string[] = [];
      let match: RegExpExecArray | null;
      
      // RegExp.exec usage - should NOT be flagged as dangerous shell execution
      while ((match = template.pattern.exec(content)) !== null) {
        const processed = template.processor(match);
        matches.push(processed);
        
        // Prevent infinite loops with global flags
        if (!template.pattern.global) {
          break;
        }
      }
      
      if (matches.length > 0) {
        results.push({
          template: template.name,
          matches: matches
        });
      }
    }
    
    return results;
  }
  
  /**
   * Validate template upload format
   * @param templateData - Raw template data
   * @returns Validation result
   */
  validateTemplate(templateData: string): {valid: boolean, errors: string[]} {
    const errors: string[] = [];
    
    try {
      // Pattern matching with exec - should not trigger false positive
      const headerPattern = /^\/\*\s*Template:\s*(.+)\s*\*\/$/m;
      const headerMatch = headerPattern.exec(templateData);
      
      if (!headerMatch) {
        errors.push('Missing template header');
      }
      
      const configPattern = /config\s*:\s*\{([^}]+)\}/;
      const configMatch = configPattern.exec(templateData);
      
      if (!configMatch) {
        errors.push('Missing configuration block');
      }
      
    } catch (error) {
      errors.push(`Template validation error: ${error}`);
    }
    
    return {
      valid: errors.length === 0,
      errors: errors
    };
  }
}