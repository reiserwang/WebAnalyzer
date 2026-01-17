import React from 'react';

// Reusing generic JSON block or building a custom table
// Custom table is better for devices/services

const IoTScannerView = ({ data }) => {
    if (!data || data.error) return <div style={{ color: 'red' }}>Scan Error: {data?.error || 'Unknown'}</div>;

    const devices = data.devices_found || [];

    return (
        <div>
            <div style={{ marginBottom: '1rem', color: '#666', fontStyle: 'italic' }}>
                {data.summary}
            </div>

            {devices.map((device, idx) => (
                <div key={idx} style={{ marginBottom: '2rem', border: '1px solid #333', padding: '1rem' }}>
                    <h4 style={{ color: '#00ff41', marginTop: 0 }}>Host: {device.ip}</h4>

                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #333', textAlign: 'left', color: '#888' }}>
                                <th style={{ padding: '0.5rem' }}>PORT</th>
                                <th style={{ padding: '0.5rem' }}>SERVICE</th>
                                <th style={{ padding: '0.5rem' }}>BANNER</th>
                                <th style={{ padding: '0.5rem' }}>HINT</th>
                            </tr>
                        </thead>
                        <tbody>
                            {device.services.map((svc, i) => (
                                <tr key={i} style={{ borderBottom: '1px solid #111' }}>
                                    <td style={{ padding: '0.5rem', color: '#00ccff' }}>{svc.port}/{svc.state}</td>
                                    <td style={{ padding: '0.5rem' }}>{svc.service}</td>
                                    <td style={{ padding: '0.5rem', color: '#aaa' }}>{svc.banner || '-'}</td>
                                    <td style={{ padding: '0.5rem' }}>
                                        {svc.device_type_hint !== 'Unknown' ? (
                                            <span style={{ border: '1px solid #00ff41', color: '#00ff41', padding: '0 4px', fontSize: '0.7rem' }}>
                                                {svc.device_type_hint}
                                            </span>
                                        ) : '-'}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ))}
        </div>
    );
};

export default {
    id: "IoT Scanner",
    name: "IoT Scanner",
    component: IoTScannerView
};
