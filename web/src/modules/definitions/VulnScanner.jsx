import React, { useState } from 'react';

const VulnScannerView = ({ data }) => {
    if (!data || data.error) return <div style={{ color: 'red' }}>Scan Error: {data?.error || 'Unknown'}</div>;

    const { vulnerabilities, snmp_info, summary } = data;
    const [expanded, setExpanded] = useState({});

    const toggle = (idx) => {
        setExpanded(prev => ({ ...prev, [idx]: !prev[idx] }));
    };

    const getSeverityColor = (sev) => {
        switch (sev) {
            case 'Critical': return '#ff0000';
            case 'High': return '#ff4141';
            case 'Medium': return '#ff9900';
            case 'Low': return '#ffff00';
            default: return '#00ccff'; // Info
        }
    };

    return (
        <div>
            {/* Summary Stats */}
            {summary && (
                <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
                    {Object.entries(summary).map(([sev, count]) => (
                        <div key={sev} style={{
                            background: '#111', border: `1px solid ${getSeverityColor(sev)}`,
                            padding: '0.5rem 1rem', borderRadius: '4px', textAlign: 'center', minWidth: '80px'
                        }}>
                            <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: getSeverityColor(sev) }}>{count}</div>
                            <div style={{ fontSize: '0.7rem', color: '#888' }}>{sev}</div>
                        </div>
                    ))}
                </div>
            )}

            {/* SNMP Info */}
            {snmp_info && Object.keys(snmp_info).length > 0 && (
                <div style={{ marginBottom: '2rem', border: '1px solid #333', background: '#0a0a0a', padding: '1rem' }}>
                    <h4 style={{ margin: '0 0 1rem 0', color: '#00ff41', borderBottom: '1px solid #333', paddingBottom: '0.5rem' }}>SNMP Enumeration (UDP 161)</h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(100px, auto) 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
                        {snmp_info.sysDescr && (
                            <>
                                <div style={{ color: '#888' }}>sysDescr:</div>
                                <div style={{ color: '#ddd' }}>{snmp_info.sysDescr}</div>
                            </>
                        )}
                        {snmp_info.details && (
                            <>
                                <div style={{ color: '#888' }}>Details:</div>
                                <div style={{ color: '#ddd', whiteSpace: 'pre-wrap' }}>{snmp_info.details}</div>
                            </>
                        )}
                        {snmp_info.processes && (
                            <>
                                <div style={{ color: '#888' }}>Processes:</div>
                                <div style={{ color: '#ddd', whiteSpace: 'pre-wrap', maxHeight: '200px', overflowY: 'auto' }}>
                                    {snmp_info.processes}
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}

            {/* Vulnerabilities List */}
            <div>
                <h4 style={{ borderBottom: '1px solid #333', color: '#888', marginBottom: '1rem' }}>Detected Vulnerabilities</h4>

                {!vulnerabilities || vulnerabilities.length === 0 ? (
                    <div style={{ color: '#666', fontStyle: 'italic' }}>No vulnerabilities detected (or safe mode skip).</div>
                ) : (
                    vulnerabilities.map((v, idx) => (
                        <div key={idx} style={{ marginBottom: '0.5rem', background: '#111', borderLeft: `3px solid ${getSeverityColor(v.severity)}` }}>
                            <div
                                onClick={() => toggle(idx)}
                                style={{ padding: '0.75rem', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                            >
                                <div>
                                    <span style={{
                                        display: 'inline-block', padding: '2px 6px', borderRadius: '3px',
                                        background: getSeverityColor(v.severity), color: '#000',
                                        fontSize: '0.7rem', fontWeight: 'bold', marginRight: '0.5rem'
                                    }}>
                                        {v.severity.toUpperCase()}
                                    </span>
                                    <span style={{ color: '#ddd', fontWeight: '500' }}>{v.title}</span>
                                </div>
                                <div style={{ color: '#666', fontSize: '0.8rem' }}>
                                    Port: {v.port}/{v.service} {expanded[idx] ? '▲' : '▼'}
                                </div>
                            </div>

                            {expanded[idx] && (
                                <div style={{
                                    padding: '0.75rem', borderTop: '1px solid #222',
                                    color: '#aaa', fontSize: '0.85rem', lineHeight: '1.4'
                                }}>
                                    {v.cve && <div style={{ marginBottom: '0.5rem', color: '#fff' }}><strong>CVE:</strong> {v.cve}</div>}
                                    <div>{v.description}</div>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default {
    id: "Vulnerability Scanner",
    name: "Vulnerability Scanner",
    component: VulnScannerView
};
