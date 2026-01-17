import React from 'react';
import { getModuleRenderer } from '../modules';
import ErrorBoundary from './ErrorBoundary';

export default function ResultsView({ results }) {
    if (!results) return null;

    return (
        <div className="brutal-border">
            <h2>// SCAN RESULTS: {results.domain}</h2>
            <div className="grid-cols-2">
                {Object.entries(results.results).map(([moduleName, moduleData]) => {
                    const Renderer = getModuleRenderer(moduleName);

                    return (
                        <div key={moduleName} style={{ marginBottom: '2rem' }}>
                            <h3 style={{ borderBottom: '1px solid #333', paddingBottom: '0.5rem', marginBottom: '1rem', fontSize: '0.9rem', color: '#00ff41' }}>
                                {moduleName}
                            </h3>
                            <div className={`json-pretty`}>
                                <ErrorBoundary>
                                    <Renderer data={moduleData} />
                                </ErrorBoundary>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
