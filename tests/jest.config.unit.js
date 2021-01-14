module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    rootDir: '../',
    testMatch: ['<rootDir>/tests/specs/**'],
    globals: {
        'ts-jest': {
            tsConfig: {
                strictPropertyInitialization: false,
                noUnusedLocals: false,
            },
        },
    },
    reporters: ['default'],
};
