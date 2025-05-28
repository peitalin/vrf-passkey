import React, { useState, useEffect } from 'react';

// Use the same pattern as WebAuthnManager
const WASM_WORKER_URL = new URL('../security/onetimePasskeySigner.worker.ts', import.meta.url);

const TestOnetimeWorker: React.FC = () => {
  const [logs, setLogs] = useState<string[]>([]);

  const logResult = (message: string, isError = false) => {
    const logEntry = `[${new Date().toLocaleTimeString()}] ${message}`;
    setLogs(prevLogs => [...prevLogs, (isError ? 'ERROR: ' : '') + logEntry]);
  };

  const clearLogs = () => {
    setLogs([]);
  };

  useEffect(() => {
    logResult('One-time worker test page loaded. Click buttons to run tests.');
  }, []);

  const testWorkerCreation = async () => {
    logResult('Starting worker creation test...');

    for (let i = 0; i < 5; i++) {
      const startTime = performance.now();

      try {
        const worker = new Worker(
          WASM_WORKER_URL,
          { type: 'module' }
        );

        const messagePromise = new Promise((resolve, reject) => {
          worker.onmessage = (event) => resolve(event.data);
          worker.onerror = (error) => reject(error);
          worker.postMessage({
            type: 'UNKNOWN_TYPE',
            payload: {}
          });
        });

        const response = await messagePromise;
        const endTime = performance.now();
        const duration = (endTime - startTime).toFixed(2);

        logResult(`Worker ${i + 1}: Created and responded in ${duration}ms. Response: ${JSON.stringify(response)}`);

        setTimeout(() => {
          let terminated = false;

          const timeoutId = setTimeout(() => {
            if (!terminated) {
              logResult(`Worker ${i + 1}: Confirmed terminated (no response after 200ms)`);
              terminated = true;
            }
          }, 200);

          worker.onmessage = () => {
            if (!terminated) {
              clearTimeout(timeoutId);
              logResult(`Worker ${i + 1}: ERROR - Worker still alive after processing!`, true);
              terminated = true;
            }
          };

          worker.onerror = () => {
            if (!terminated) {
              clearTimeout(timeoutId);
              logResult(`Worker ${i + 1}: Confirmed terminated (worker error on message)`);
              terminated = true;
            }
          };

          try {
            worker.postMessage({ type: 'TEST', payload: {} });
          } catch (e) {
            if (!terminated) {
              clearTimeout(timeoutId);
              logResult(`Worker ${i + 1}: Confirmed terminated (postMessage threw error)`);
              terminated = true;
            }
          }
        }, 100);

      } catch (error: any) {
        logResult(`Worker ${i + 1}: Error - ${error.message}`, true);
      }
      await new Promise(resolve => setTimeout(resolve, 800));
    }
  };

  const testWasmCaching = async () => {
    logResult('Testing WASM cache status...');
    try {
      const cache = await caches.open('passkey-wasm-v1');
      const keys = await cache.keys();

      if (keys.length > 0) {
        logResult(`WASM cache contains ${keys.length} entries:`);
        for (const request of keys) {
          const response = await cache.match(request);
          const size = response?.headers.get('content-length') || 'unknown';
          logResult(`  - ${request.url} (size: ${size} bytes)`);
        }
      } else {
        logResult('WASM cache is empty');
      }

      logResult('\nTesting cache performance...');
      const start1 = performance.now();
      const worker1 = new Worker(WASM_WORKER_URL, { type: 'module' });
      await new Promise(resolve => {
        worker1.onmessage = resolve;
        worker1.postMessage({ type: 'TEST', payload: {} });
      });
      const time1 = performance.now() - start1;

      const start2 = performance.now();
      const worker2 = new Worker(WASM_WORKER_URL, { type: 'module' });
      await new Promise(resolve => {
        worker2.onmessage = resolve;
        worker2.postMessage({ type: 'TEST', payload: {} });
      });
      const time2 = performance.now() - start2;

      logResult(`First worker initialization: ${time1.toFixed(2)}ms`);
      logResult(`Second worker initialization: ${time2.toFixed(2)}ms`);
      logResult(`Cache speedup: ${((time1 - time2) / time1 * 100).toFixed(1)}%`);

    } catch (error: any) {
      logResult(`Cache test error: ${error.message}`, true);
    }
  };

  const clearWasmCache = async () => {
    logResult('Clearing WASM cache...');
    try {
      const deleted = await caches.delete('passkey-wasm-v1');
      if (deleted) {
        logResult('WASM cache cleared successfully');
      } else {
        logResult('WASM cache was not found or already empty');
      }
    } catch (error: any) {
      logResult(`Error clearing cache: ${error.message}`, true);
    }
  };

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>One-Time Worker Pattern Test</h1>
      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
        <h2>Test Controls</h2>
        <button onClick={testWorkerCreation} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>Test Worker Creation (5x)</button>
        <button onClick={testWasmCaching} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>Test WASM Caching</button>
        <button onClick={clearWasmCache} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>Clear WASM Cache</button>
        <button onClick={clearLogs} style={{ padding: '10px 20px', margin: '5px', cursor: 'pointer' }}>Clear Logs</button>
      </div>
      <div style={{ margin: '20px 0', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
        <h2>Test Results</h2>
        <div id="results">
          {logs.map((log, index) => (
            <div key={index} style={{ background: '#f5f5f5', padding: '10px', margin: '10px 0', borderRadius: '3px', fontFamily: 'monospace', fontSize: '12px', whiteSpace: 'pre-wrap', color: log.startsWith('ERROR:') ? 'red' : 'inherit' }}>
              {log}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default TestOnetimeWorker;
