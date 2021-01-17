import jwtDecoder from 'jwt-decode';
import createError from 'http-errors';

export type JwtToken = {
    iss: string;
    sub: string;
};

export type Rule = (token: JwtToken) => Promise<RuleResult>;

export type RuleResult = {
    passed: boolean;
    ruleName: string;
};

export type Request = {
    headers: {
        authorization: string;
    };
};

export const authorize = async (
    jwtToken: string,
    executionRule: Rule
): Promise<void> => {
    const token = parseToken(jwtToken);

    if (!token.iss) {
        throw createError(403, 'invalid token (missing issuer)');
    }

    const ruleResult = await executionRule(token);
    if (!ruleResult.passed) {
        throw createError(403, 'Operation not authorized');
    }
};

export const and = (rules: Rule[]): Rule => async (token: JwtToken) => {
    for (const rule of rules) {
        const ruleResult = await rule(token);
        if (!ruleResult.passed) {
            return ruleResult;
        }
    }
    return {passed: true, ruleName: 'and'};
};

export const or = (rules: Rule[]): Rule => async (token: JwtToken) => {
    for (const rule of rules) {
        const ruleResult = await rule(token);
        if (ruleResult.passed) return {passed: true, ruleName: 'or'};
    }
    return {passed: false, ruleName: 'or'};
};

const parseToken = (token: string): JwtToken & {iss: string} => jwtDecoder(token);
