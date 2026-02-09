import js from '@eslint/js';

export default [
  {
    ignores: ['node_modules/**', '.next/**', 'out/**', 'dist/**'],
  },
  js.configs.recommended,
  {
    rules: {
      'no-unused-vars': 'warn',
      'no-undef': 'warn'
    }
  }
];
