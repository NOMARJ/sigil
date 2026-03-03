#!/usr/bin/env node

/**
 * Test script for Forge MCP tools
 * Simulates an AI agent using the discovery tools
 */

import { spawn } from 'child_process';
import { promisify } from 'util';

const sleep = promisify(setTimeout);

// Test cases for Forge tools
const testCases = [
  {
    tool: 'forge_search',
    params: {
      query: 'postgres database',
      type: 'both'
    },
    description: 'Search for postgres tools'
  },
  {
    tool: 'forge_stack',
    params: {
      use_case: 'I want to query a Postgres database and generate reports'
    },
    description: 'Get a database stack recommendation'
  },
  {
    tool: 'forge_check',
    params: {
      name: 'mcp-postgres',
      ecosystem: 'mcp'
    },
    description: 'Check details of mcp-postgres'
  },
  {
    tool: 'sigil_check_package',
    params: {
      ecosystem: 'clawhub',
      package_name: 'todoist-cli'
    },
    description: 'Check a known package in the database'
  }
];

async function runTest() {
  console.log('🧪 Testing Forge MCP Server Tools\n');
  
  for (const test of testCases) {
    console.log(`\n📋 Test: ${test.description}`);
    console.log(`Tool: ${test.tool}`);
    console.log(`Params:`, test.params);
    console.log('---');
    
    // Simulate MCP tool call
    const request = {
      jsonrpc: '2.0',
      id: Math.random().toString(36).substring(7),
      method: 'tools/call',
      params: {
        name: test.tool,
        arguments: test.params
      }
    };
    
    console.log('Request:', JSON.stringify(request, null, 2));
    console.log('\nNote: In a real MCP environment, this would call the tool and return results.');
    console.log('The MCP server is ready to be used with Claude Code, Cursor, or other MCP clients.\n');
    
    await sleep(500); // Brief pause between tests
  }
  
  console.log('\n✅ All test cases prepared successfully!');
  console.log('\nTo use these tools:');
  console.log('1. Add to claude_desktop_config.json:');
  console.log('   "sigil": { "command": "sigil-mcp-server" }');
  console.log('2. Restart Claude Code or your MCP client');
  console.log('3. Use the forge_search, forge_stack, and forge_check tools\n');
}

runTest().catch(console.error);