import { useState } from 'react';

import { REGISTERED_MODULES } from '../modules';

const MODULES = REGISTERED_MODULES.map(m => m.name);

export default function ScannerForm({ onSubmit, isLoading }) {
    const [domain, setDomain] = useState('');
    const [selectedModules, setSelectedModules] = useState([]);

    const toggleModule = (mod) => {
        if (selectedModules.includes(mod)) {
            setSelectedModules(selectedModules.filter(m => m !== mod));
        } else {
            setSelectedModules([...selectedModules, mod]);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (domain) {
            onSubmit(domain, selectedModules.length > 0 ? selectedModules : null);
        }
    };

    return (
        <div className="brutal-border">
            <h2>// SYSTEM TARGET</h2>
            <form onSubmit={handleSubmit}>
                <div style={{ marginBottom: '1.5rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#666' }}>
                        ENTER TARGET DOMAIN
                    </label>
                    <input
                        type="text"
                        placeholder="example.com"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        disabled={isLoading}
                    />
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#666' }}>
                        SELECT MODULES (EMPTY = ALL)
                    </label>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {MODULES.map(mod => (
                            <div
                                key={mod}
                                onClick={() => !isLoading && toggleModule(mod)}
                                style={{
                                    border: '1px solid #333',
                                    padding: '0.25rem 0.5rem',
                                    cursor: isLoading ? 'default' : 'pointer',
                                    fontSize: '0.8rem',
                                    background: selectedModules.includes(mod) ? '#333' : 'transparent',
                                    color: selectedModules.includes(mod) ? '#fff' : '#666',
                                    userSelect: 'none'
                                }}
                            >
                                {mod}
                            </div>
                        ))}
                    </div>
                </div>

                <button type="submit" disabled={isLoading || !domain}>
                    {isLoading ? 'ANALYZING...' : 'INITIATE SCAN'}
                </button>

                {isLoading && <div className="loading-bar"></div>}
            </form>
        </div>
    );
}
