module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    rootDir: '../',
    testMatch: [
        '<rootDir>/tests/specs/**',
    ],
    reporters: [
        'default',
    ],
}