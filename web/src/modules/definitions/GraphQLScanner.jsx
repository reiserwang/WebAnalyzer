import React from 'react';

const GraphQLScannerView = ({ data }) => {
    if (!data || data.error) return null;

    const { introspection, depth_limit } = data;

    const StatusBadge = ({ label, status, details }) => {
        const isVuln = status === "Vulnerable";
        const color = isVuln ? '#ff3333' : '#00ff41';
        return (
            <div style={{ marginBottom: '1rem', borderLeft: `3px solid ${color}`, paddingLeft: '1rem' }}>
                <div style={{ fontWeight: 'bold', color: '#fff', fontSize: '0.9rem', marginBottom: '0.25rem' }}>{label}</div>
                <div style={{ fontSize: '0.85rem', color: color, marginBottom: '0.15rem' }}>{status}</div>
                <div style={{ fontSize: '0.8rem', color: '#888' }}>{details}</div>
            </div>
        );
    };

    return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <StatusBadge label="INTROSPECTION" {...introspection} />
            <StatusBadge label="QUERY DEPTH" {...depth_limit} />
        </div>
    );
};

export default {
    id: "GraphQL Scanner",
    name: "GraphQL Scanner",
    component: GraphQLScannerView
};
