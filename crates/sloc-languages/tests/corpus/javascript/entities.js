import { foo } from './foo';

class Calculator {
    add(a, b) {
        return a + b;
    }
}

function multiply(a, b) {
    let result = a * b;
    return result;
}

const divide = (a, b) => a / b;

describe('Calculator', () => {
    it('should add', () => {
        expect(1 + 1).toBe(2);
    });

    test('should multiply', () => {
        expect(multiply(2, 3)).toBe(6);
    });
});
