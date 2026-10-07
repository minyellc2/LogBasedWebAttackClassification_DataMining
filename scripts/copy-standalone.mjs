import { cpSync, existsSync } from 'node:fs';

if (existsSync('.next/static')) {
  cpSync('.next/static', '.next/standalone/.next/static', { recursive: true });
}
if (existsSync('public')) {
  cpSync('public', '.next/standalone/public', { recursive: true });
}
console.log('Standalone assets copied.');
