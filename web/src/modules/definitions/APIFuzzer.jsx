import React from 'react';

const APIFuzzerView = ({ data }) => {
    if (!data || data.error) {
        return <div style={{ color: '#ff3333', padding: '1rem', border: '1px solid #ff3333' }}>{data?.details || data?.error || "Error running module"}</div>;
    }

    const { schema_source, endpoints_found, findings } = data;

    return (
        <div>
            <div style={{ marginBottom: '1rem', fontSize: '0.85rem', color: '#888', borderBottom: '1px solid #333', paddingBottom: '0.5rem' }}>
                <span style={{ marginRight: '1rem' }}>SCHEMA: <span style={{ color: '#fff' }}>{schema_source}</span></span>
                <span>ENDPOINTS: <span style={{ color: '#fff' }}>{endpoints_found}</span></span>
            </div>

            {findings && findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {findings.map((f, i) => (
                        <div key={i} style={{ border: '1px solid #222', padding: '0.5rem', background: 'rgba(0,0,0,0.2)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                                <span style={{ color: '#00ff41', fontSize: '0.9rem', fontFamily: 'monospace' }}>{f.endpoint}</span>
                                <span style={{ fontSize: '0.75rem', padding: '2px 6px', background: '#333', borderRadius: '4px' }}>{f.status}</span>
                            </div>
                            <div style={{ fontSize: '0.8rem', color: '#aaa' }}>{f.details}</div>
                        </div>
                    ))}
                </div>
            ) : (
                <div style={{ color: '#666', fontStyle: 'italic' }}>No specific findings reported.</div>
            )}
        </div>
    );
};

export default {
    id: "API Fuzzer",
    name: "API Fuzzer",
    component: APIFuzzerView
};
