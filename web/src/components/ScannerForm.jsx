import { useState } from 'react';

import { REGISTERED_MODULES, MODULE_CATEGORIES } from '../modules';

const MODULES = REGISTERED_MODULES.map(m => m.name);

export default function ScannerForm({ onSubmit, isLoading }) {
    const [domain, setDomain] = useState('');
    const [selectedModules, setSelectedModules] = useState([]);
    const [schemaUrl, setSchemaUrl] = useState('');
    const [scanMode, setScanMode] = useState('domain'); // 'domain' or 'local'

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
            // Pass options as third argument
            onSubmit(domain, selectedModules.length > 0 ? selectedModules : null, {
                schema_url: schemaUrl,
                scan_mode: scanMode
            });
        }
    };

    return (
        <div className="brutal-border">
            <h2>// SYSTEM TARGET</h2>
            <form onSubmit={handleSubmit}>
                <div style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <label style={{ fontSize: '0.8rem', color: '#666' }}>SCAN MODE:</label>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button
                            type="button"
                            onClick={() => {
                                setScanMode('domain');
                                if (domain === '192.168.1.0/24') setDomain('');
                            }}
                            style={{
                                background: scanMode === 'domain' ? '#00ff41' : 'transparent',
                                color: scanMode === 'domain' ? '#000' : '#666',
                                border: '1px solid #333',
                                padding: '0.25rem 0.75rem',
                                fontSize: '0.8rem',
                                cursor: 'pointer'
                            }}
                        >
                            DOMAIN
                        </button>
                        <button
                            type="button"
                            onClick={() => {
                                setScanMode('local');
                                if (!domain) setDomain('192.168.1.0/24');
                            }}
                            style={{
                                background: scanMode === 'local' ? '#00ff41' : 'transparent',
                                color: scanMode === 'local' ? '#000' : '#666',
                                border: '1px solid #333',
                                padding: '0.25rem 0.75rem',
                                fontSize: '0.8rem',
                                cursor: 'pointer'
                            }}
                        >
                            LOCAL NETWORK
                        </button>
                    </div>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#666' }}>
                        {scanMode === 'domain' ? 'ENTER TARGET DOMAIN' : 'ENTER LOCAL SUBNET (CIDR)'}
                    </label>
                    <input
                        type="text"
                        placeholder={scanMode === 'domain' ? "example.com" : "192.168.1.0/24"}
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        disabled={isLoading}
                        data-testid="domain-input"
                    />
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#666' }}>
                        SELECT MODULES (EMPTY = ALL)
                    </label>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                        {Object.entries(MODULE_CATEGORIES).map(([category, modules]) => (
                            <div key={category}>
                                <h3 style={{
                                    fontSize: '0.85rem',
                                    color: category.includes('Exploitation') ? '#ff3333' :
                                        category.includes('Recon') ? '#00ff41' : '#fff',
                                    marginBottom: '0.5rem',
                                    textTransform: 'uppercase',
                                    borderBottom: '1px solid #333',
                                    paddingBottom: '0.25rem'
                                }}>
                                    {category}
                                </h3>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                                    {modules.map(mod => (
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
                                                userSelect: 'none',
                                                transition: 'all 0.2s ease',
                                                opacity: (scanMode === 'local' && ['SEO Analysis', 'Domain Information', 'Contact Spy'].includes(mod)) ? 0.3 : 1
                                            }}
                                        >
                                            {mod}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Conditional Input for API Fuzzer */}
                {(selectedModules.length === 0 || selectedModules.includes("API Fuzzer")) && scanMode === 'domain' && (
                    <div style={{ marginBottom: '1.5rem', borderLeft: '2px solid #00ff41', paddingLeft: '1rem', marginLeft: '-1rem' }}>
                        <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.8rem', color: '#00ff41' }}>
                            OPENAPI SCHEMA URL (REQUIRED FOR API FUZZER)
                        </label>
                        <input
                            type="text"
                            placeholder="http://example.com/openapi.json"
                            value={schemaUrl}
                            onChange={(e) => setSchemaUrl(e.target.value)}
                            disabled={isLoading}
                            style={{ borderColor: '#00ff41' }}
                            data-testid="schema-input"
                        />
                    </div>
                )}

                <button type="submit" disabled={isLoading || !domain}>
                    {isLoading ? 'ANALYZING...' : 'INITIATE SCAN'}
                </button>

                {isLoading && <div className="loading-bar"></div>}
            </form>
        </div>
    );
}
