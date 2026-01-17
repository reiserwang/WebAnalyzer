import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const ConsoleOutput = () => {
    const [logs, setLogs] = useState([]);
    const bottomRef = useRef(null);

    // Fetch logs every 2 seconds
    useEffect(() => {
        const fetchLogs = async () => {
            try {
                // Use default base URL from axios config or relative path
                const res = await axios.get('http://127.0.0.1:8000/api/logs?limit=50');
                if (res.data && res.data.logs) {
                    setLogs(res.data.logs);
                }
            } catch (error) {
                console.error("Failed to fetch logs:", error);
            }
        };

        const interval = setInterval(fetchLogs, 2000);
        fetchLogs(); // Initial fetch

        return () => clearInterval(interval);
    }, []);

    // Auto-scroll to bottom of the container
    useEffect(() => {
        if (bottomRef.current) {
            bottomRef.current.scrollTop = bottomRef.current.scrollHeight;
        }
    }, [logs]);

    return (
        <div className="brutal-border" style={{ marginTop: '2rem', background: '#000' }}>
            <h2>// SYSTEM STATUS LOG</h2>
            <div
                ref={bottomRef}
                style={{
                    height: '200px',
                    overflowY: 'auto',
                    padding: '1rem',
                    background: '#0a0a0a',
                    border: '1px solid #333',
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: '#aaa',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.25rem'
                }}>
                {logs.length === 0 ? (
                    <div style={{ fontStyle: 'italic', color: '#444' }}>Waiting for system logs...</div>
                ) : (
                    logs.map((log, index) => (
                        <div key={index} style={{ wordBreak: 'break-all' }}>
                            <span style={{ color: '#00ff41', marginRight: '0.5rem' }}>&gt;</span>
                            {log}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default ConsoleOutput;
