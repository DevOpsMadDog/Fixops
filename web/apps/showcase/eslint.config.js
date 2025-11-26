import nextPlugin from 'eslint-config-next';

export default [
  {
    ignores: ['.next/**', 'out/**', 'dist/**', 'node_modules/**'],
  },
  ...nextPlugin,
];
