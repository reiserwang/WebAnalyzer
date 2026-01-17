import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const JobStatus = ({ job }) => {
    const [status, setStatus] = useState(job.status);

    useEffect(() => {
        // Only poll if it's running or started
        if (status !== 'started' && status !== 'running') return;

        const interval = setInterval(async () => {
            try {
                const res = await axios.get(`${API_BASE}/api/msf/job/${job.job_id}`);
                if (res.data && res.data.status) {
                    setStatus(res.data.status);
                    if (res.data.status === 'completed' || res.data.status === 'error') {
                        clearInterval(interval);
                    }
                }
            } catch (e) {
                console.error("Polling error", e);
            }
        }, 3000); // Poll every 3 seconds

        return () => clearInterval(interval);
    }, [job.job_id, status]);

    const getStatusColor = (s) => {
        if (s === 'running' || s === 'started') return '#00ccff'; // Blue for active
        if (s === 'completed') return '#00ff41'; // Green for done
        if (s === 'error') return '#ff4141';
        return '#ccc';
    };

    return (
        <span style={{
            fontWeight: 'bold',
            color: getStatusColor(status),
            fontSize: '0.9rem'
        }}>
            {status === 'running' || status === 'started' ? (
                <span>Running (Job #{typeof job.job_id === 'object' ? 'ERR' : job.job_id})...</span>
            ) : (typeof status === 'object' ? JSON.stringify(status) : status)}
        </span>
    );
};

const ScanGroup = ({ title, scans }) => {
    if (!scans || Object.keys(scans).length === 0) return null;

    return (
        <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ borderBottom: '1px solid #333', color: '#888', marginBottom: '0.5rem' }}>{title}</h4>
            {Object.entries(scans).map(([key, items]) => (
                <div key={key} style={{ marginBottom: '1rem', paddingLeft: '0.5rem' }}>
                    <h5 style={{ color: '#00ccff', margin: '0 0 0.5rem 0' }}>{key}</h5>
                    {Array.isArray(items) ? items.map((job, idx) => (
                        <div key={idx} style={{
                            background: '#111', border: '1px solid #222',
                            padding: '0.5rem', marginBottom: '0.25rem', fontSize: '0.8rem',
                            display: 'flex', justifyContent: 'space-between'
                        }}>
                            <span style={{ color: '#ccc' }}>{job.module}</span>
                            <JobStatus job={job} />
                        </div>
                    )) : (
                        <div style={{ color: 'red' }}>Invalid format</div>
                    )}
                </div>
            ))}
        </div>
    );
};

const MSFDeepScanView = ({ data }) => {
    const renderError = (err) => {
        if (!err) return 'Unknown';
        try {
            return typeof err === 'object' ? JSON.stringify(err) : String(err);
        } catch {
            return 'Error rendering message';
        }
    };

    if (!data || data.error) return <div style={{ color: 'red' }}>Scan Error: {renderError(data?.error)}</div>;

    const { tech_scans, cve_sweeps, ssl_analysis, errors } = data;
    const hasData = (tech_scans && Object.keys(tech_scans).length > 0) ||
        (cve_sweeps && Object.keys(cve_sweeps).length > 0) ||
        (ssl_analysis && Object.keys(ssl_analysis).length > 0);

    return (
        <div>
            {!hasData && !errors?.length && <div style={{ color: '#666' }}>No scans triggered.</div>}

            <ScanGroup title="Technology Specific Scans" scans={tech_scans} />

            {/* CVE Sweeps Section */}
            {cve_sweeps && Object.keys(cve_sweeps).length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ borderBottom: '1px solid #333', color: '#ff4141', marginBottom: '0.5rem' }}>High-Profile CVE Sweeps</h4>
                    {Object.entries(cve_sweeps).map(([cve, job]) => (
                        <div key={cve} style={{
                            background: '#221111', border: '1px solid #ff4141',
                            padding: '0.75rem', marginBottom: '0.5rem',
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                        }}>
                            <div>
                                <div style={{ fontWeight: 'bold', color: '#ff4141' }}>{cve}</div>
                                <div style={{ fontSize: '0.75rem', color: '#888' }}>{job.module}</div>
                            </div>
                            <JobStatus job={job} />
                        </div>
                    ))}
                </div>
            )}

            {/* SSL/TLS Analysis Section */}
            {ssl_analysis && Object.keys(ssl_analysis).length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ borderBottom: '1px solid #333', color: '#ff9900', marginBottom: '0.5rem' }}>SSL/TLS Analysis</h4>
                    {Object.entries(ssl_analysis).map(([check, job]) => (
                        <div key={check} style={{
                            background: '#110f0a', border: '1px solid #ff9900',
                            padding: '0.75rem', marginBottom: '0.5rem',
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                        }}>
                            <div>
                                <div style={{ fontWeight: 'bold', color: '#ff9900' }}>{check}</div>
                                <div style={{ fontSize: '0.75rem', color: '#888' }}>{job.module}</div>
                            </div>
                            <JobStatus job={job} />
                        </div>
                    ))}
                </div>
            )}

            {errors && errors.length > 0 && (
                <div style={{ borderTop: '1px solid #333', paddingTop: '1rem' }}>
                    <h5 style={{ color: 'red' }}>Runtime Errors</h5>
                    {errors.map((e, i) => <div key={i} style={{ color: 'red', fontSize: '0.8rem' }}>{renderError(e)}</div>)}
                </div>
            )}

            <div style={{ marginTop: '1rem', padding: '0.5rem', border: '1px dashed #333', fontSize: '0.8rem', color: '#666' }}>
                ℹ️ These scans run as background jobs on your <strong>local Metasploit instance</strong>.
                Use <code>msfconsole</code> to check precise output of jobs.
            </div>
        </div>
    );
};

export default {
    id: "MSF Deep Scan",
    name: "MSF Deep Scan",
    component: MSFDeepScanView
};
