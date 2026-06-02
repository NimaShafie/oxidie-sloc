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
        expect(new Calculator().add(1, 1)).toBe(2);
    });

    test('should multiply', () => {
        foo();
        divide(2, 3);
        expect(multiply(2, 3)).toBe(6);
    });
});
