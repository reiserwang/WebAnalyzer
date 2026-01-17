import React, { useState } from 'react';
import axios from 'axios';

// Note: In real app, this should be an environment variable or prop passed down
const API_BASE = 'http://localhost:8000';

const SuggestionCard = ({ item }) => {
    const [status, setStatus] = useState(null); // null, 'loading', 'checked', 'error'
    const [result, setResult] = useState(null);

    const handleVerify = async () => {
        setStatus('loading');
        try {
            const payload = {
                module: item.module,
                options: { RHOSTS: '127.0.0.1' }, // Default to localhost or need current target context
                // In a real flow, we need the target domain/IP from the scan context.
                // For now, let's assume RHOSTS needs to be passed, but the `execute_module` 
                // might handle context if improved.
                // Let's assume user must configure options or we default safe.
                action: 'check'
            };

            const response = await axios.post(`${API_BASE}/api/msf/execute`, payload);
            setResult(response.data);
            setStatus('checked');
        } catch (err) {
            setResult({ status: 'error', message: err.message });
            setStatus('error');
        }
    };

    return (
        <div style={{ background: '#111', padding: '1rem', marginBottom: '0.5rem', borderLeft: '2px solid #00ff41' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span style={{ color: '#00ff41', fontWeight: 'bold', fontSize: '0.9rem' }}>{item.module}</span>
                <span style={{
                    fontSize: '0.7rem',
                    padding: '0.1rem 0.4rem',
                    borderRadius: '2px',
                    background: item.type.includes('High') ? '#ff4141' : '#333'
                }}>
                    {item.type}
                </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: '#888' }}>
                {item.description}
            </div>
            {item.indicator && (
                <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.5rem' }}>
                    Trigger: {item.indicator}
                </div>
            )}

            {/* Verify Button Area */}
            <div style={{ marginTop: '0.75rem', borderTop: '1px solid #222', paddingTop: '0.5rem' }}>
                {status === 'loading' ? (
                    <span style={{ fontSize: '0.8rem', color: '#aaa' }}>Verifying...</span>
                ) : (
                    <button
                        onClick={handleVerify}
                        style={{
                            background: '#333', border: '1px solid #444', color: '#ddd',
                            fontSize: '0.75rem', padding: '4px 8px', cursor: 'pointer'
                        }}
                    >
                        ▶ Verify (Check Mode)
                    </button>
                )}

                {result && (
                    <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#ccc', fontFamily: 'monospace', background: '#000', padding: '0.5rem' }}>
                        {JSON.stringify(result, null, 2)}
                    </div>
                )}
            </div>
        </div>
    );
};

const MetasploitView = ({ data }) => {
    if (!data || data.error) return <div style={{ color: 'red' }}>Module Error: {data?.error || 'Unknown'}</div>;

    // data is the array of suggestions
    if (!Array.isArray(data) || data.length === 0) {
        return <div style={{ color: '#666' }}>No modules suggested based on current scan findings.</div>;
    }

    return (
        <div>
            {data.map((item, idx) => (
                <SuggestionCard key={idx} item={item} />
            ))}
            <div style={{ marginTop: '1rem', padding: '0.5rem', border: '1px dashed #333', fontSize: '0.8rem', color: '#666' }}>
                ℹ️ To execute checks, ensure Metasploit RPC (msfrpcd) is running.
                <br />
                This sends <code>action='check'</code> to the backend.
            </div>
        </div>
    );
};

export default {
    id: "Metasploit Suggester",
    name: "Metasploit Suggester",
    component: MetasploitView
};
