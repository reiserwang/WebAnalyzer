import { useState } from 'react';
import axios from 'axios';
import ScannerForm from './components/ScannerForm';
import ResultsView from './components/ResultsView';

const API_URL = 'http://localhost:8000/api/scan';

function App() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (domain, modules) => {
    setLoading(true);
    setResults(null);
    setError(null);

    try {
      const payload = {
        domain,
        modules,
        run_all: !modules
      };

      const response = await axios.post(API_URL, payload);
      setResults(response.data);
    } catch (err) {
      console.error("Scanning Error Details:", {
        message: err.message,
        response: err.response,
        request: err.request,
        config: err.config
      });

      let errorMessage = 'Failed to connect to server';
      if (err.response?.data?.detail) {
        errorMessage = `API Error: ${err.response.data.detail}`;
      } else if (err.message) {
        errorMessage = `Network Error: ${err.message}`;
      }

      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <header style={{ marginBottom: '3rem', borderBottom: '1px solid #333', paddingBottom: '1rem' }}>
        <h1 style={{ fontSize: '2rem', margin: 0 }}>
          WEB<span style={{ color: 'var(--accent-color)' }}>ANALYZER</span>
          <span style={{ fontSize: '0.8rem', marginLeft: '1rem', color: '#666', verticalAlign: 'middle' }}>v2.0</span>
        </h1>
      </header>

      <ScannerForm onSubmit={handleScan} isLoading={loading} />

      {loading && (
        <div className="brutal-border" style={{ borderColor: 'var(--accent-color)', color: 'var(--accent-color)', textAlign: 'center', padding: '2rem' }}>
          <h2 className="glitch" data-text="INITIALIZING SCAN">INITIALIZING SCAN protocols...</h2>
          <p>Please wait while we interrogate the target.</p>
        </div>
      )}

      {error && (
        <div className="brutal-border" style={{ borderColor: 'red', color: 'red' }}>
          <h3>// SYSTEM ERROR</h3>
          <p>{error}</p>
        </div>
      )}

      <ResultsView results={results} />
    </div>
  );
}

export default App;
