import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import App from './App';

// Mock axios
vi.mock('axios');

// Mock the modules
vi.mock('./modules', () => ({
    REGISTERED_MODULES: [
        { name: 'Domain Information', id: 'Domain Information' },
        { name: 'DNS Records', id: 'DNS Records' },
        { name: 'API Fuzzer', id: 'API Fuzzer' }
    ],
    MODULE_CATEGORIES: {
        "Category 1": ["Domain Information"],
        "Category 2": ["DNS Records", "API Fuzzer"]
    },
    getModuleRenderer: () => () => <div>MockComponent</div>
}));

vi.mock('./components/ConsoleOutput', () => ({
    default: () => <div data-testid="console-output">MockConsoleOutput</div>
}));

describe('App Component', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    it('renders the title', () => {
        render(<App />);
        expect(screen.getByText(/WEB/i)).toBeInTheDocument();
        expect(screen.getByText(/ANALYZER/i)).toBeInTheDocument();
    });

    it('handles successful scan', async () => {
        const mockData = {
            results: {
                "Domain Information": { Domain: "example.com" }
            }
        };
        axios.post.mockResolvedValueOnce({ data: mockData });

        render(<App />);

        // Find input and type domain
        const input = screen.getByTestId('domain-input');
        fireEvent.change(input, { target: { value: 'example.com' } });

        // Click scan button
        const button = screen.getByRole('button', { name: /initiate scan/i });
        fireEvent.click(button);

        // Check loading state
        expect(screen.getByText(/INITIALIZING SCAN/i)).toBeInTheDocument();

        // Wait for results
        await waitFor(() => {
            expect(screen.queryByText(/INITIALIZING SCAN/i)).not.toBeInTheDocument();
        });

        // Check if ResultsView renders module keys (mocked result)
        expect(screen.getByRole('heading', { name: 'Domain Information', level: 3 })).toBeInTheDocument();
    });

    it('handles API error', async () => {
        const errorMessage = "Invalid domain";
        axios.post.mockRejectedValueOnce({
            response: { data: { detail: errorMessage } }
        });

        render(<App />);

        const input = screen.getByTestId('domain-input');
        fireEvent.change(input, { target: { value: 'bad-domain' } });

        // Click scan (assuming same button)
        const button = screen.getByRole('button');
        fireEvent.click(button);

        await waitFor(() => {
            expect(screen.getByText(/SYSTEM ERROR/i)).toBeInTheDocument();
            expect(screen.getByText(`API Error: ${errorMessage}`)).toBeInTheDocument();
        });
    });
    it('shows schema input when API Fuzzer is selected', async () => {
        render(<App />);

        // Find module selection for API Fuzzer and DNS Records
        const apiOption = screen.getByText('API Fuzzer');
        const dnsOption = screen.getByText('DNS Records');

        // 1. Initial State (Empty = Run All) -> Input SHOULD be visible
        expect(screen.getByTestId('schema-input')).toBeInTheDocument();

        // 2. Select ONLY DNS Records -> Input should DISAPPEAR
        fireEvent.click(dnsOption);
        await waitFor(() => {
            expect(screen.queryByTestId('schema-input')).not.toBeInTheDocument();
        });

        // 3. Select API Fuzzer -> Input should APPEAR
        fireEvent.click(apiOption);
        expect(screen.getByTestId('schema-input')).toBeInTheDocument();
    });
});
