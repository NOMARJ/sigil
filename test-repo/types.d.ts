// TypeScript definition file - these should NOT trigger execution warnings
export interface Editor {
  exec(command: string): void;
  eval(expression: string): any;
}

declare function eval(code: string): any;

class CommandExecutor {
  exec(cmd: string): Promise<void>;
  system(command: string): number;
}

// These are just type definitions - they don't execute anything
type ExecFunction = (code: string) => void;
type EvalFunction = (expr: string) => any;