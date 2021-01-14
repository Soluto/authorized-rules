import jwtDecoder from 'jwt-decode';
import createError from 'http-errors';

export type JwtToken = {
    iss: string;
    sub: string;
};

export type Rule<T> = (token: JwtToken) => Promise<RuleResult<T>>;

export type RuleResult<T extends {}> = {
    passed: boolean;
    data: T[];
    ruleName: string;
};

export type Request = {
    headers: {
        authorization: string;
    };
};

export const authorize = async <T1 = void, T2 = void, T3 = void, T4 = void>(
    jwtToken: string,
    executionRule: Rule<T1 | T2 | T3 | T4>
): Promise<(T1 | T2 | T3 | T4)[]> => {
    const token = getToken(jwtToken);

    if (!token.iss) {
        throw createError(403, 'invalid token (missing issuer)');
    }

    const ruleResult = await executionRule(token);
    if (!ruleResult.passed) {
        throw createError(403, 'Operation not authorized');
    }

    return ruleResult.data;
};

export const and = <T extends {} | void>(rules: Rule<T>[]): Rule<T> => async (token: JwtToken) => {
    let data: T[] = [];
    for (const rule of rules) {
        const ruleResult = await rule(token);
        if (!ruleResult.passed) {
            return ruleResult;
        }
        data = [...data, ...ruleResult.data];
    }
    return {passed: true, ruleName: 'and', data};
};

export const or = <T extends {} | void>(rules: Rule<T>[]): Rule<T> => async (token: JwtToken) => {
    let data: T[] = [];
    for (const rule of rules) {
        const ruleResult = await rule(token);
        data = [...data, ...ruleResult.data];
        if (ruleResult.passed) return {passed: true, ruleName: 'or', data};
    }
    return {passed: false, ruleName: 'or', data: []};
};

const getToken = (token: string): JwtToken & {iss: string} => jwtDecoder(token);
