import { describe, it, expect } from 'vitest';
import { REGISTERED_MODULES, MODULE_CATEGORIES } from './index';

describe('Module Categorization', () => {
    it('should include all registered modules in categories', () => {
        const registeredNames = new Set(REGISTERED_MODULES.map(m => m.name));
        const categorizedNames = new Set();

        Object.values(MODULE_CATEGORIES).forEach(modules => {
            modules.forEach(m => categorizedNames.add(m));
        });

        // Check for missing modules
        const missing = [...registeredNames].filter(x => !categorizedNames.has(x));

        if (missing.length > 0) {
            console.error("Missing modules:", missing);
        }

        expect(missing).toEqual([]);
    });

    it('should not include unknown modules in categories', () => {
        const registeredNames = new Set(REGISTERED_MODULES.map(m => m.name));
        const extra = [];

        Object.entries(MODULE_CATEGORIES).forEach(([cat, modules]) => {
            modules.forEach(m => {
                if (!registeredNames.has(m)) {
                    extra.push(`${cat}: ${m}`);
                }
            });
        });

        if (extra.length > 0) {
            console.error("Unknown modules in categories:", extra);
        }

        expect(extra).toEqual([]);
    });
});
