import React from 'react';

const PortTable = ({ data }) => {
    if (!data || data.error) return null;

    const { open_ports, services } = data;
    if (!open_ports || open_ports.length === 0) {
        return <div style={{ color: '#666' }}>No open ports found.</div>;
    }

    return (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
                <tr style={{ borderBottom: '1px solid #333', textAlign: 'left' }}>
                    <th style={{ padding: '0.5rem', color: '#888' }}>PORT</th>
                    <th style={{ padding: '0.5rem', color: '#888' }}>SERVICE</th>
                    <th style={{ padding: '0.5rem', color: '#888' }}>VERSION</th>
                </tr>
            </thead>
            <tbody>
                {open_ports.map(port => {
                    const service = services[port] || {};
                    return (
                        <tr key={port} style={{ borderBottom: '1px solid #111' }}>
                            <td style={{ padding: '0.5rem', color: '#00ff41' }}>{port}</td>
                            <td style={{ padding: '0.5rem' }}>{service.service || 'unknown'}</td>
                            <td style={{ padding: '0.5rem', color: '#aaa' }}>{service.version || 'unknown'}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
};

export default {
    id: "Port Scan",
    name: "Port Scan",
    component: PortTable
};
