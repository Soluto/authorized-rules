import * as jwt from 'jsonwebtoken';
import {and, authorize, or, Rule, RuleResult} from '../../src/index';

type Value = {
    value: string;
};

const jwtToken = 
    jwt.sign(
        {
            sub: "222222",
            client_id: "'some-client-id'",
            grant_type: 'client_credentials',
            iss: 'some-issuer',
        },
        'secret'
    );

const createRule = (ruleName: string, passed: boolean, data: Value[]) => (): Rule<Value> => async (): Promise<
    RuleResult<Value>
> => ({
    ruleName,
    passed,
    data,
});

describe('tests', () => {
    describe('and', () => {
        it('all rules should pass', async () => {
            const rule1 = createRule('rule1', true, []);
            const rule2 = createRule('rule2', true, []);

            await authorize(jwtToken, and([rule1(), rule2()]));
        });

        it('gathers all data results', async () => {
            const rule1 = createRule('rule1', true, [{value: 'value1'}]);
            const rule2 = createRule('rule2', true, [{value: 'value2'}]);

            const [result1, result2] = await authorize<Value, Value>(jwtToken, and([rule1(), rule2()]));
            expect(result1 && result1.value).toBe('value1');
            expect(result2 && result2.value).toBe('value2');
        });
    });

    describe('or', () => {
        it('one of the rules should pass', async () => {
            const rule1 = createRule('rule1', true, []);
            const rule2 = createRule('rule2', false, []);

            await authorize(jwtToken, or([rule1(), rule2()]));
            await authorize(jwtToken, or([rule2(), rule1()]));
        });
        it('gathers all results until the rule that passed', async () => {
            const rule1 = createRule('rule1', true, [{value: 'value1'}]);
            const rule2 = createRule('rule2', false, [{value: 'value2'}]);

            let [result1, result2] = await authorize(jwtToken, or([rule1(), rule2()]));
            expect(result1.value).toBe('value1');
            expect(result2).toBeUndefined();

            [result2, result1] = await authorize(jwtToken, or([rule2(), rule1()]));
            expect(result2.value).toBe('value2');
            expect(result1.value).toBe('value1');
        });
    });
});
