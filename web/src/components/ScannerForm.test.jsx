import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ScannerForm from './ScannerForm';

describe('ScannerForm UI Logic', () => {
    it('enables submit button when domain is entered in local mode', async () => {
        const handleSubmit = vi.fn();
        render(<ScannerForm onSubmit={handleSubmit} isLoading={false} />);

        const submitBtn = screen.getByRole('button', { name: /INITIATE SCAN/i });
        const localBtn = screen.getByRole('button', { name: /LOCAL NETWORK/i });
        const domainInput = screen.getByTestId('domain-input');

        // Initially disabled
        expect(submitBtn).toBeDisabled();

        // Switch to Local Mode
        await act(async () => {
            fireEvent.click(localBtn);
        });

        // Enter IP
        await act(async () => {
            fireEvent.change(domainInput, { target: { value: '192.168.1.1' } });
        });

        // Should be enabled
        expect(submitBtn).not.toBeDisabled();

        // Click
        fireEvent.click(submitBtn);

        // Verify submit called with correct mode
        expect(handleSubmit).toHaveBeenCalledWith(
            '192.168.1.1',
            null, // modules (empty = null)
            expect.objectContaining({ scan_mode: 'local' })
        );
    });
});
