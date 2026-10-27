import { useCallback, useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [packetLimit, setPacketLimit] = useState(500);
  const [duration, setDuration] = useState(60);
  const [bpfFilter, setBpfFilter] = useState('');
  const [status, setStatus] = useState({ running: false, packet_count: 0 });
  const [packets, setPackets] = useState([]);
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [expandedPacket, setExpandedPacket] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);

  const request = useCallback(async (path, options = {}) => {
    const response = await fetch(`${API_BASE}${path}`, options);
    const contentType = response.headers.get('content-type') || '';
    if (!response.ok) {
      const body = contentType.includes('application/json') ? await response.json() : null;
      throw new Error(body?.message || `Request failed (${response.status})`);
    }
    return contentType.includes('application/json') ? response.json() : response;
  }, []);

  const loadInterfaces = useCallback(async () => {
    const data = await request('/api/interfaces');
    setInterfaces(data);
    setSelectedInterface((current) => current || data[0]?.name || '');
  }, [request]);

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextPackets] = await Promise.all([
        request('/api/status'),
        request('/api/packets'),
      ]);
      setStatus(nextStatus);
      setPackets(nextPackets);
      setConnected(true);
      if (nextStatus.error) setError(`Capture error: ${nextStatus.error}`);
    } catch {
      setConnected(false);
    }
  }, [request]);

  useEffect(() => {
    loadInterfaces().catch(() => {
      setConnected(false);
      setError('Backend unavailable. Start the API server, then retry.');
    });
    refresh();
    const timer = window.setInterval(refresh, 1500);
    return () => window.clearInterval(timer);
  }, [loadInterfaces, refresh]);

  const protocolCounts = useMemo(() => {
    const counts = {};
    packets.forEach(({ protocol }) => {
      const key = protocol || 'UNKNOWN';
      counts[key] = (counts[key] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [packets]);

  const filteredPackets = useMemo(() => {
    const query = search.trim().toLowerCase();
    return [...packets].reverse().filter((packet) => {
      const protocolMatches = protocolFilter === 'ALL' || packet.protocol === protocolFilter;
      const searchable = [packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol, packet.dns_query]
        .filter(Boolean).join(' ').toLowerCase();
      return protocolMatches && (!query || searchable.includes(query));
    });
  }, [packets, protocolFilter, search]);

  const startCapture = async () => {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const data = await request('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedInterface,
          packet_limit: Number(packetLimit),
          duration: Number(duration),
          bpf_filter: bpfFilter.trim() || null,
        }),
      });
      if (data.status !== 'started') throw new Error(data.message || 'Capture could not start.');
      setNotice(`Capture started on ${selectedInterface}.`);
      await refresh();
    } catch (err) {
      setError(err.message || 'Capture request failed.');
    } finally {
      setBusy(false);
    }
  };

  const stopCapture = async () => {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await request('/api/capture/stop', { method: 'POST' });
      setNotice('Capture stopped.');
      await refresh();
    } catch (err) {
      setError(err.message || 'Unable to stop capture.');
    } finally {
      setBusy(false);
    }
  };

  const clearPackets = async () => {
    setError('');
    setNotice('');
    try {
      await request('/api/packets/clear', { method: 'POST' });
      setExpandedPacket(null);
      setNotice('Packet history cleared.');
      await refresh();
    } catch (err) {
      setError(err.message || 'Unable to clear packet history.');
    }
  };

  const exportPackets = async (format) => {
    setError('');
    try {
      const response = await request(`/api/packets/export?format=${format}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `packets.${format}`;
      link.click();
      URL.revokeObjectURL(url);
      setNotice(`Exported ${packets.length} packets as ${format.toUpperCase()}.`);
    } catch (err) {
      setError(err.message || 'Unable to export packets.');
    }
  };

  const running = Boolean(status.running);
  const selectedDetails = interfaces.find((item) => item.name === selectedInterface);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">N</div>
          <div>
            <p className="eyebrow">Network operations · packet observability</p>
            <h1>Basic Network Sniffer</h1>
            <p className="subtitle">Live traffic analysis for authorized networks</p>
          </div>
        </div>
        <div className="header-meta">
          <span className={`connection-indicator ${connected ? 'online' : ''}`}>
            <i /> {connected ? 'API connected' : 'API disconnected'}
          </span>
          <span className={`status-pill ${running ? 'live' : ''}`}>
            <i /> {running ? 'Capturing' : 'Ready'}
          </span>
        </div>
      </header>

      <main className="dashboard">
        {(error || notice) && (
          <div className={`message-banner ${error ? 'error-box' : 'success-box'}`} role={error ? 'alert' : 'status'}>
            <span>{error || notice}</span>
            <button className="message-dismiss" onClick={() => { setError(''); setNotice(''); }} aria-label="Dismiss message">×</button>
          </div>
        )}

        <section className="card capture-panel">
          <div className="section-heading">
            <div><p className="eyebrow">Capture configuration</p><h2>Session controls</h2></div>
            <span className="muted">Choose an interface and capture scope</span>
          </div>
          <div className="controls">
            <label className="field field-interface">
              Network interface
              <select value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)} disabled={running || busy}>
                {interfaces.length === 0 && <option value="">No interfaces available</option>}
                {interfaces.map((iface) => <option key={iface.name} value={iface.name}>{iface.name} · {iface.ip_address || 'No IPv4 address'}</option>)}
              </select>
              {selectedDetails && <small>MAC {selectedDetails.mac_address || 'unavailable'} · {selectedDetails.is_active ? 'address assigned' : 'no address'}</small>}
            </label>
            <label className="field">
              Packet limit
              <input type="number" value={packetLimit} min="1" max="100000" onChange={(event) => setPacketLimit(event.target.value)} disabled={running || busy} />
              <small>1–100,000 packets</small>
            </label>
            <label className="field">
              Duration
              <div className="input-suffix"><input type="number" value={duration} min="1" max="3600" onChange={(event) => setDuration(event.target.value)} disabled={running || busy} /><span>sec</span></div>
              <small>1–3,600 seconds</small>
            </label>
            <label className="field field-filter">
              Capture filter (BPF)
              <input type="text" value={bpfFilter} placeholder="tcp port 443 · udp port 53" onChange={(event) => setBpfFilter(event.target.value)} disabled={running || busy} />
              <small>Optional Scapy/libpcap filter</small>
            </label>
            <div className="actions">
              <button className="primary start-button" onClick={startCapture} disabled={running || busy || !selectedInterface || !connected}>
                <span className="button-icon">▶</span>{busy && !running ? 'Starting…' : 'Start capture'}
              </button>
              <button className="stop-button" onClick={stopCapture} disabled={!running || busy}>
                <span className="button-icon">■</span>{busy && running ? 'Stopping…' : 'Stop capture'}
              </button>
            </div>
          </div>
          <div className="capture-footnote"><span>Only monitor networks you own or have permission to inspect.</span><span>{running ? `Interface: ${status.interface || selectedInterface}` : 'Capture is currently stopped'}</span></div>
        </section>

        <section className="grid-metrics" aria-label="Capture metrics">
          <div className="card metric"><span className="metric-label">Packets captured</span><strong>{status.packet_count ?? 0}</strong><small>Current in-memory session</small></div>
          <div className="card metric"><span className="metric-label">Protocols observed</span><strong>{protocolCounts.length}</strong><small>Distinct protocol types</small></div>
          <div className="card metric"><span className="metric-label">Capture interface</span><strong className="metric-text">{status.interface || selectedInterface || '—'}</strong><small>{selectedDetails?.ip_address || 'No interface selected'}</small></div>
          <div className="card metric"><span className="metric-label">Session started</span><strong className="metric-text">{status.created_at ? new Date(status.created_at * 1000).toLocaleTimeString() : '—'}</strong><small>{running ? 'Active session' : 'No active session'}</small></div>
        </section>

        <section className="analysis-grid">
          <div className="card protocol-card">
            <div className="section-heading compact"><div><p className="eyebrow">Traffic overview</p><h2>Protocol distribution</h2></div></div>
            {protocolCounts.length === 0 ? <div className="empty-state">Protocol activity will appear when packets are captured.</div> : (
              <ul className="protocol-list">
                {protocolCounts.slice(0, 7).map(([protocol, count]) => (
                  <li key={protocol}><span className="protocol-name"><i className={`protocol-dot protocol-${protocol.toLowerCase()}`} />{protocol}</span><span className="protocol-count">{count}</span><div className="protocol-bar"><i style={{ width: `${Math.max(4, (count / Math.max(...protocolCounts.map((entry) => entry[1]))) * 100)}%` }} /></div></li>
                ))}
              </ul>
            )}
          </div>

          <section className="card table-card">
            <div className="table-heading">
              <div><p className="eyebrow">Live packet stream</p><h2>Captured packets <span className="result-count">{filteredPackets.length}</span></h2></div>
              <div className="table-actions">
                <button className="utility-button" onClick={() => exportPackets('csv')} disabled={packets.length === 0}>Export CSV</button>
                <button className="utility-button" onClick={() => exportPackets('json')} disabled={packets.length === 0}>Export JSON</button>
                <button className="utility-button danger-utility" onClick={clearPackets} disabled={running || packets.length === 0}>Clear</button>
              </div>
            </div>
            <div className="table-filters">
              <label className="search-field"><span aria-hidden="true">⌕</span><input aria-label="Search packets" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search addresses, ports, DNS…" /></label>
              <select aria-label="Filter by protocol" value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
                <option value="ALL">All protocols</option>
                {protocolCounts.map(([protocol]) => <option key={protocol} value={protocol}>{protocol}</option>)}
              </select>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th aria-label="Details" /></tr></thead>
                <tbody>
                  {filteredPackets.length === 0 && <tr><td colSpan="6" className="empty-table">{packets.length ? 'No packets match the current filters.' : 'No packets captured yet. Start a session to begin inspection.'}</td></tr>}
                  {filteredPackets.map((packet, index) => {
                    const rowId = `${packet.timestamp}-${index}`;
                    return (
                      <FragmentRows key={rowId} packet={packet} rowId={rowId} expanded={expandedPacket === rowId} onToggle={() => setExpandedPacket(expandedPacket === rowId ? null : rowId)} />
                    );
                  })}
                </tbody>
              </table>
            </div>
            <footer className="table-footer"><span>Showing {filteredPackets.length} of {packets.length} captured packets</span><span>Updates automatically every 1.5 seconds</span></footer>
          </section>
        </section>
      </main>
      <footer className="app-footer"><span>Basic Network Sniffer <b>·</b> Educational traffic analysis</span><span>Capture responsibly. Authorization required.</span></footer>
    </div>
  );
}

function FragmentRows({ packet, rowId, expanded, onToggle }) {
  const endpoint = (address, port) => `${address || '—'}${port ? `:${port}` : ''}`;
  return (
    <>
      <tr className={expanded ? 'packet-row expanded' : 'packet-row'} onClick={onToggle} tabIndex="0" onKeyDown={(event) => { if (event.key === 'Enter') onToggle(); }}>
        <td>{packet.timestamp ? new Date(packet.timestamp).toLocaleTimeString() : '—'}</td>
        <td><span className="protocol-tag">{packet.protocol || 'UNKNOWN'}</span></td>
        <td className="endpoint-cell">{endpoint(packet.src_ip, packet.src_port)}</td>
        <td className="endpoint-cell">{endpoint(packet.dst_ip, packet.dst_port)}</td>
        <td>{packet.length ?? 0} B</td>
        <td><button className="expand-button" onClick={(event) => { event.stopPropagation(); onToggle(); }} aria-label={expanded ? 'Hide packet details' : 'Show packet details'}>{expanded ? '−' : '+'}</button></td>
      </tr>
      {expanded && <tr className="detail-row"><td colSpan="6"><div className="packet-details">
        <span><b>Interface</b>{packet.interface || '—'}</span><span><b>TTL / Hop limit</b>{packet.ttl ?? '—'}</span>
        <span><b>DNS query</b>{packet.dns_query || '—'}</span><span><b>Ethernet source</b>{packet.eth_src || '—'}</span>
        <span><b>Ethernet destination</b>{packet.eth_dst || '—'}</span><span><b>ICMP type / code</b>{packet.icmp_type ?? '—'} / {packet.icmp_code ?? '—'}</span>
        {packet.payload_hex && <span className="payload-detail"><b>Payload (hex preview)</b><code>{packet.payload_hex.slice(0, 160)}{packet.payload_hex.length > 160 ? '…' : ''}</code></span>}
      </div></td></tr>}
    </>
  );
}

export default App;
