module.exports = {
    parser: '@typescript-eslint/parser',
    parserOptions: {
        sourceType: 'module',
    },
    plugins: ['@typescript-eslint', 'simple-import-sort'],
    overrides: [
        {
            files: '*',
            rules: {
                'simple-import-sort/sort': 'error',
            },
        },
    ],
};
