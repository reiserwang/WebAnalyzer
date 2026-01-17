import React from 'react';

const TopologyGraphView = ({ data }) => {
    if (!data || data.error) return <div style={{ color: 'red' }}>Scan Error: {data?.error || 'Unknown'}</div>;

    const { hops, target } = data;

    if (!hops || hops.length === 0) {
        return <div style={{ color: '#666' }}>No route data available (traceroute failed).</div>;
    }

    // Styling constants
    const LINE_COLOR = '#00ff41';
    const NODE_COLOR = '#111';
    const NODE_BORDER = '#00ff41';

    return (
        <div style={{ padding: '1rem', background: '#050505', border: '1px solid #222' }}>
            <h4 style={{ color: '#00ccff', marginBottom: '1.5rem', borderBottom: '1px dashed #333', paddingBottom: '0.5rem' }}>
                Route to {target}
            </h4>

            <div style={{ position: 'relative', paddingLeft: '20px' }}>
                {hops.map((hop, index) => (
                    <div key={index} style={{ position: 'relative', marginBottom: '1.5rem', display: 'flex', alignItems: 'center' }}>
                        {/* Vertical Line */}
                        {index < hops.length - 1 && (
                            <div style={{
                                position: 'absolute',
                                left: '15px',
                                top: '30px',
                                bottom: '-30px',
                                width: '2px',
                                background: LINE_COLOR,
                                zIndex: 0
                            }}></div>
                        )}

                        {/* Node Circle */}
                        <div style={{
                            width: '32px', height: '32px',
                            borderRadius: '50%',
                            background: NODE_COLOR,
                            border: `2px solid ${NODE_BORDER}`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            zIndex: 1,
                            marginRight: '1rem',
                            fontWeight: 'bold', fontSize: '0.8rem', color: '#fff'
                        }}>
                            {hop.ttl}
                        </div>

                        {/* Hop Details */}
                        <div style={{
                            background: '#111', padding: '0.5rem 1rem',
                            borderLeft: '4px solid #333', flex: 1,
                            borderRadius: '2px'
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                                <span style={{ color: '#fff', fontWeight: 'bold' }}>
                                    {hop.ip || hop.host || '***'}
                                </span>
                                <span style={{ color: '#00ccff', fontSize: '0.8rem' }}>
                                    {hop.rtt}
                                </span>
                            </div>
                            {hop.host && hop.host !== hop.ip && (
                                <div style={{ fontSize: '0.75rem', color: '#666' }}>{hop.host}</div>
                            )}
                            {(!hop.ip && !hop.host) && (
                                <div style={{ fontSize: '0.75rem', color: '#444', fontStyle: 'italic' }}>Request Timed Out</div>
                            )}
                        </div>
                    </div>
                ))}

                {/* Target Node (Final) */}
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center', marginTop: '0.5rem' }}>
                    <div style={{
                        width: '40px', height: '40px',
                        borderRadius: '50%',
                        background: '#ff4141',
                        border: `2px solid #fff`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        zIndex: 1,
                        marginRight: '1rem',
                        fontWeight: 'bold', fontSize: '1.2rem'
                    }}>
                        🎯
                    </div>
                    <div style={{ color: '#ff4141', fontWeight: 'bold', fontSize: '1.1rem' }}>
                        TARGET: {target}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default {
    id: "Network Topology",
    name: "Network Topology",
    component: TopologyGraphView
};
