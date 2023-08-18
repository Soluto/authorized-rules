import * as jwt from 'jsonwebtoken';
import {HttpError} from 'http-errors';
import {and, authorize, or, Rule, RuleResult} from '../../src/index';

const jwtToken = jwt.sign(
    {
        sub: '222222',
        client_id: "'some-client-id'",
        grant_type: 'client_credentials',
        iss: 'some-issuer',
    },
    'secret'
);

const createRule = (ruleName: string, passed: boolean) => (): Rule => async (): Promise<RuleResult> => ({
    ruleName,
    passed,
});

describe('tests', () => {
    describe('and', () => {
        it('all rules should pass', async () => {
            const rule1 = createRule('rule1', true);
            const rule2 = createRule('rule2', true);

            await authorize(jwtToken, and([rule1(), rule2()]));
        });
    });

    describe('or', () => {
        it('one of the rules should pass', async () => {
            const rule1 = createRule('rule1', true,);
            const rule2 = createRule('rule2', false);

            await authorize(jwtToken, or([rule1(), rule2()]));
            await authorize(jwtToken, or([rule2(), rule1()]));
        });
    });

    describe('authorize', () => {
        it('should throw 403 when rule does not pass', async () => {
            expect.assertions(1);

            const rule1 = createRule('rule1', false);

            try {
                await authorize(jwtToken, and([rule1()]));
            } catch (e) {
                if (e instanceof HttpError) {
                    expect(e.status).toBe(403);
                }
            }
        });

        it('should throw 403 when token in invalid ', async () => {
            expect.assertions(1);

            const rule1 = createRule('rule1', false);

            try {
                await authorize('stam', and([rule1()]));
            } catch (e) {
                if (e instanceof HttpError) {
                    expect(e.status).toBe(403);
                }
            }
        });        
    });    
});
