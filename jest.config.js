/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  setupFiles: ['dotenv/config', '<rootDir>/tests/helpers/setup-env.ts'],
  moduleNameMapper: {
    '^@test/(.*)$': '<rootDir>/tests/helpers/$1',
  },
  collectCoverageFrom: ['src/**/*.ts'],
  coveragePathIgnorePatterns: ['/dist/', '\\.d\\.ts$'],
  clearMocks: true,
};
