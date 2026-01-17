import React, { useState } from 'react';

// Status colors
const STATUS_COLORS = {
    "Running": "#00ff41",
    "Completed": "#00ccff",
    "Error": "#ff4141",
    "Unknown": "#666"
};

const MSFJobMonitor = ({ data }) => {
    if (!data) return null;
    if (data.error) return <div style={{ color: 'red' }}>Error: {data.error}</div>;

    const { active_jobs_count, jobs } = data;

    if (!jobs || jobs.length === 0) {
        return (
            <div style={{ padding: '1rem', color: '#888', fontStyle: 'italic' }}>
                No active Metasploit jobs running.
            </div>
        );
    }

    return (
        <div style={{ padding: '1rem', background: '#050505', border: '1px solid #222' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #333', paddingBottom: '0.5rem' }}>
                <h4 style={{ margin: 0, color: '#fff' }}>Active Jobs ({active_jobs_count})</h4>
                <div style={{ fontSize: '0.8rem', color: '#666' }}>ID: Job Name</div>
            </div>

            <div style={{ display: 'grid', gap: '0.5rem' }}>
                {jobs.map((job) => (
                    <div key={job.id} style={{
                        background: '#111',
                        padding: '0.75rem',
                        borderLeft: `3px solid ${STATUS_COLORS[job.status] || STATUS_COLORS.Unknown}`,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.25rem'
                    }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ fontWeight: 'bold', color: '#fff' }}>{job.name}</span>
                            <span style={{
                                fontSize: '0.75rem',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                background: 'rgba(255,255,255,0.1)',
                                color: STATUS_COLORS[job.status] || '#fff'
                            }}>
                                {job.status}
                            </span>
                        </div>
                        <div style={{ fontSize: '0.8rem', color: '#666', fontFamily: 'monospace' }}>
                            Job ID: {job.id}
                        </div>
                        {job.start_time && (
                            <div style={{ fontSize: '0.75rem', color: '#444' }}>
                                Started: {new Date(job.start_time * 1000).toLocaleString()}
                            </div>
                        )}
                        {/* Optional: Show datastore options if available */}
                        {job.datastore && (
                            <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#aaa', borderTop: '1px solid #222', paddingTop: '0.25rem' }}>
                                <div style={{ marginBottom: '2px', color: '#666' }}>Options:</div>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#888' }}>
                                    {JSON.stringify(job.datastore, null, 2)}
                                </pre>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
};

export default {
    id: "MSF Job Monitor",
    name: "MSF Job Monitor",
    component: MSFJobMonitor
};
