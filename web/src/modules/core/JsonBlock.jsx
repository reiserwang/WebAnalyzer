import React from 'react';

const SEVERITY_COLORS = {
    CRITICAL: '#ff0000',
    HIGH: '#ff4141',
    MEDIUM: '#ff9f41',
    LOW: '#00ccff',
    INFO: '#666'
};

const getSeverityColor = (val) => {
    if (!val) return null;
    const s = String(val).toUpperCase();
    if (s.includes('CRITICAL')) return SEVERITY_COLORS.CRITICAL;
    if (s.includes('HIGH')) return SEVERITY_COLORS.HIGH;
    if (s.includes('MEDIUM')) return SEVERITY_COLORS.MEDIUM;
    if (s.includes('LOW')) return SEVERITY_COLORS.LOW;
    return null;
};

const JsonBlock = ({ data }) => {
    // 1. Primitive handling
    if (typeof data !== 'object' || data === null) {
        const color = getSeverityColor(data);
        return <span style={{ color: color || '#00ff41' }}>{String(data)}</span>;
    }

    // 2. Array handling
    if (Array.isArray(data)) {
        if (data.length === 0) return <span style={{ color: '#666' }}>[]</span>;
        return (
            <ul style={{ paddingLeft: '1rem', borderLeft: '1px solid #333' }}>
                {data.map((item, index) => (
                    <li key={index} style={{ listStyle: 'none', margin: '0.25rem 0' }}>
                        <JsonBlock data={item} />
                    </li>
                ))}
            </ul>
        );
    }

    // 3. Object handling
    if (Object.keys(data).length === 0) return <span style={{ color: '#666' }}>{'{}'}</span>;

    // Check if this object represents a risk/severity item
    // e.g. { severity: "High", ... } or { severity: { level: "High" } }
    let borderColor = '#333'; // Default border
    let bgColor = 'transparent';

    const severityVal = data.severity || data.risk || data.priority;
    if (severityVal) {
        // If severity is an object (e.g. { level: 'High', score: 9 }), check level
        const level = typeof severityVal === 'object' ? severityVal.level : severityVal;
        const detectedColor = getSeverityColor(level);
        if (detectedColor) {
            borderColor = detectedColor;
            bgColor = `${detectedColor}11`; // Very transparent background
        }
    }

    return (
        <div style={{
            paddingLeft: '1rem',
            borderLeft: `2px solid ${borderColor}`,
            background: bgColor,
            padding: '0.5rem',
            marginBottom: '0.5rem'
        }}>
            {Object.entries(data).map(([key, value]) => (
                <div key={key} style={{ margin: '0.25rem 0' }}>
                    <span style={{ color: '#888', marginRight: '0.5rem' }}>{key}:</span>
                    <JsonBlock data={value} />
                </div>
            ))}
        </div>
    );
};

export default JsonBlock;
