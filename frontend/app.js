const { useState, useEffect, useCallback, createContext, useContext } = React;

// --- API Client ---
const API_BASE = 'http://localhost:8000/api/v1';

async function fetchAPI(endpoint, options = {}) {
    try {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        if (!res.ok) throw new Error(`API Error: ${res.status}`);
        return await res.json();
    } catch (err) {
        console.error('API Error:', err);
        return null;
    }
}

// --- Context ---
const AppContext = createContext();

// --- Components ---

function SeverityBadge({ severity }) {
    const colors = {
        critical: 'bg-red-500/20 text-red-400 border-red-500/30',
        high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
        medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
        low: 'bg-green-500/20 text-green-400 border-green-500/30',
    };
    return (
        <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${colors[severity] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'}`}>
            {severity}
        </span>
    );
}

function StatCard({ title, value, change, icon, color }) {
    const colorMap = {
        red: 'from-red-500/20 to-red-600/5 border-red-500/20',
        orange: 'from-orange-500/20 to-orange-600/5 border-orange-500/20',
        blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/20',
        green: 'from-green-500/20 to-green-600/5 border-green-500/20',
        purple: 'from-purple-500/20 to-purple-600/5 border-purple-500/20',
    };
    return (
        <div className={`bg-gradient-to-br ${colorMap[color] || colorMap.blue} border rounded-xl p-5 card-hover`}>
            <div className="flex items-center justify-between mb-3">
                <span className="text-gray-400 text-sm font-medium">{title}</span>
                <span className="text-2xl">{icon}</span>
            </div>
            <div className="text-3xl font-bold text-white mb-1">{value}</div>
            {change && (
                <div className={`text-xs font-medium ${change > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {change > 0 ? '↑' : '↓'} {Math.abs(change)}% from last week
                </div>
            )}
        </div>
    );
}

function CVEItem({ cve, onClick }) {
    return (
        <div
            onClick={() => onClick(cve)}
            className="bg-dark-800 border border-dark-600 rounded-lg p-4 cursor-pointer card-hover hover:border-accent-500/30 slide-in"
        >
            <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-3">
                    <span className="font-mono text-sm text-accent-400 font-semibold">{cve.cve_id}</span>
                    <SeverityBadge severity={cve.severity} />
                </div>
                <div className="flex items-center gap-2">
                    {cve.risk_score && (
                        <span className="text-xs font-mono text-gray-400 bg-dark-700 px-2 py-1 rounded">
                            Risk: {cve.risk_score}
                        </span>
                    )}
                    <span className="text-xs font-mono text-gray-400 bg-dark-700 px-2 py-1 rounded">
                        CVSS: {cve.cvss_score}
                    </span>
                </div>
            </div>
            <p className="text-gray-300 text-sm line-clamp-2 mb-3">{cve.description}</p>
            <div className="flex items-center justify-between text-xs text-gray-500">
                <span>Published: {cve.published_date ? new Date(cve.published_date).toLocaleDateString() : 'N/A'}</span>
                {cve.exploits && cve.exploits.length > 0 && (
                    <span className="text-red-400 font-medium">⚠ {cve.exploits.length} exploit(s) available</span>
                )}
            </div>
        </div>
    );
}

function CVEDetail({ cve, onClose }) {
    if (!cve) return null;
    return (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
            <div className="bg-dark-800 border border-dark-600 rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6 slide-in" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <h2 className="text-xl font-bold font-mono text-accent-400">{cve.cve_id}</h2>
                        <SeverityBadge severity={cve.severity} />
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">&times;</button>
                </div>
                <p className="text-gray-300 mb-4 leading-relaxed">{cve.description}</p>
                <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="bg-dark-700 rounded-lg p-3">
                        <div className="text-xs text-gray-500 mb-1">CVSS Score</div>
                        <div className="text-2xl font-bold">{cve.cvss_score}</div>
                    </div>
                    <div className="bg-dark-700 rounded-lg p-3">
                        <div className="text-xs text-gray-500 mb-1">Risk Score</div>
                        <div className="text-2xl font-bold text-accent-400">{cve.risk_score || 'N/A'}</div>
                    </div>
                </div>
                {cve.exploits && cve.exploits.length > 0 && (
                    <div className="mb-4">
                        <h3 className="text-sm font-semibold text-red-400 mb-2">⚠ Known Exploits ({cve.exploits.length})</h3>
                        {cve.exploits.map((exp, i) => (
                            <div key={i} className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-2">
                                <div className="flex items-center justify-between">
                                    <span className="font-mono text-sm text-red-300">{exp.title}</span>
                                    {exp.verified && <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">Verified</span>}
                                </div>
                                <div className="text-xs text-gray-500 mt-1">{exp.type} • {exp.platform}</div>
                            </div>
                        ))}
                    </div>
                )}
                {cve.references && cve.references.length > 0 && (
                    <div>
                        <h3 className="text-sm font-semibold text-gray-400 mb-2">References</h3>
                        <div className="space-y-1">
                            {cve.references.slice(0, 5).map((ref, i) => (
                                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                    className="block text-xs text-accent-400 hover:text-accent-300 truncate">
                                    {ref}
                                </a>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

function TrendChart({ data }) {
    const canvasRef = React.useRef(null);
    const chartRef = React.useRef(null);

    useEffect(() => {
        if (!data || !canvasRef.current) return;
        const ctx = canvasRef.current.getContext('2d');

        if (chartRef.current) chartRef.current.destroy();

        chartRef.current = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(d => d.date),
                datasets: [
                    { label: 'Critical', data: data.map(d => d.critical), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.4 },
                    { label: 'High', data: data.map(d => d.high), borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.1)', fill: true, tension: 0.4 },
                    { label: 'Medium', data: data.map(d => d.medium), borderColor: '#eab308', backgroundColor: 'rgba(234,179,8,0.1)', fill: true, tension: 0.4 },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#9ca3af', font: { family: 'Inter' } } },
                },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#6b7280' } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#6b7280' } },
                },
            },
        });

        return () => { if (chartRef.current) chartRef.current.destroy(); };
    }, [data]);

    return <canvas ref={canvasRef} className="w-full h-64" />;
}

// --- Main App ---
function App() {
    const [cves, setCves] = useState([]);
    const [trends, setTrends] = useState([]);
    const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
    const [selectedCve, setSelectedCve] = useState(null);
    const [severityFilter, setSeverityFilter] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('dashboard');

    const loadData = useCallback(async () => {
        setLoading(true);
        const [cvesData, trendsData, distData] = await Promise.all([
            fetchAPI(`/cves?limit=20&severity=${severityFilter}`),
            fetchAPI('/stats/trends?days=30'),
            fetchAPI('/stats/severity-distribution'),
        ]);
        if (cvesData) setCves(cvesData.data || []);
        if (trendsData) setTrends(trendsData.data || []);
        if (distData) setStats(distData.data || {});
        setLoading(false);
    }, [severityFilter]);

    useEffect(() => { loadData(); }, [loadData]);

    const handleSearch = (e) => {
        e.preventDefault();
        setLoading(true);
        fetchAPI(`/cves?search=${encodeURIComponent(searchQuery)}&limit=20`).then(data => {
            if (data) setCves(data.data || []);
            setLoading(false);
        });
    };

    return (
        <div className="min-h-screen bg-dark-900">
            {/* Header */}
            <header className="bg-dark-800 border-b border-dark-600 sticky top-0 z-40">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-accent-500 rounded-lg flex items-center justify-center text-white font-bold text-sm glow">V</div>
                        <h1 className="text-xl font-bold">VulnScope</h1>
                        <span className="text-xs bg-accent-500/20 text-accent-400 px-2 py-0.5 rounded-full font-medium">v1.0</span>
                    </div>
                    <nav className="flex items-center gap-1">
                        {['dashboard', 'cves', 'alerts', 'api'].map(tab => (
                            <button key={tab} onClick={() => setActiveTab(tab)}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === tab ? 'bg-accent-500/20 text-accent-400' : 'text-gray-400 hover:text-white hover:bg-dark-700'}`}>
                                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                            </button>
                        ))}
                    </nav>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-6">
                {activeTab === 'dashboard' && (
                    <>
                        {/* Stats Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
                            <StatCard title="Total CVEs" value={stats.total || '—'} change={12} icon="📊" color="blue" />
                            <StatCard title="Critical" value={stats.critical || '—'} change={8} icon="🔴" color="red" />
                            <StatCard title="High" value={stats.high || '—'} change={-3} icon="🟠" color="orange" />
                            <StatCard title="Medium" value={stats.medium || '—'} change={5} icon="🟡" color="blue" />
                            <StatCard title="Low" value={stats.low || '—'} change={-1} icon="🟢" color="green" />
                        </div>

                        {/* Trend Chart */}
                        <div className="bg-dark-800 border border-dark-600 rounded-xl p-5 mb-6">
                            <h2 className="text-lg font-semibold mb-4">30-Day Vulnerability Trends</h2>
                            <TrendChart data={trends} />
                        </div>

                        {/* Search & Filter */}
                        <div className="flex items-center gap-4 mb-4">
                            <form onSubmit={handleSearch} className="flex-1 flex gap-2">
                                <input type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                                    placeholder="Search CVEs by keyword..."
                                    className="flex-1 bg-dark-800 border border-dark-600 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-accent-500 transition-colors" />
                                <button type="submit" className="bg-accent-500 hover:bg-accent-600 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-colors">
                                    Search
                                </button>
                            </form>
                            <div className="flex gap-1">
                                {['', 'critical', 'high', 'medium', 'low'].map(sev => (
                                    <button key={sev} onClick={() => setSeverityFilter(sev)}
                                        className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${severityFilter === sev ? 'bg-accent-500/20 text-accent-400' : 'bg-dark-700 text-gray-400 hover:text-white'}`}>
                                        {sev || 'All'}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* CVE List */}
                        <div className="space-y-3">
                            {loading ? (
                                <div className="text-center py-12 text-gray-500">Loading CVEs...</div>
                            ) : cves.length === 0 ? (
                                <div className="text-center py-12 text-gray-500">No CVEs found. Try adjusting your filters.</div>
                            ) : (
                                cves.map(cve => <CVEItem key={cve.cve_id} cve={cve} onClick={setSelectedCve} />)
                            )}
                        </div>
                    </>
                )}

                {activeTab === 'cves' && (
                    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
                        <h2 className="text-lg font-semibold mb-4">All CVEs</h2>
                        <p className="text-gray-400 text-sm">Browse and search all tracked vulnerabilities. Use the dashboard for quick overview.</p>
                    </div>
                )}

                {activeTab === 'alerts' && (
                    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
                        <h2 className="text-lg font-semibold mb-4">Alert Configuration</h2>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Severity Filters</label>
                                <div className="flex gap-2">
                                    {['critical', 'high', 'medium', 'low'].map(sev => (
                                        <label key={sev} className="flex items-center gap-2 bg-dark-700 px-3 py-2 rounded-lg cursor-pointer hover:bg-dark-600">
                                            <input type="checkbox" className="rounded bg-dark-600 border-dark-500 text-accent-500 focus:ring-accent-500" />
                                            <span className="text-sm capitalize">{sev}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Keywords (comma-separated)</label>
                                <input type="text" placeholder="e.g., apache, linux, remote code execution"
                                    className="w-full bg-dark-700 border border-dark-600 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-accent-500" />
                            </div>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Notification Channels</label>
                                <div className="flex gap-2">
                                    {['Slack', 'Discord', 'Telegram', 'Email'].map(ch => (
                                        <label key={ch} className="flex items-center gap-2 bg-dark-700 px-3 py-2 rounded-lg cursor-pointer hover:bg-dark-600">
                                            <input type="checkbox" className="rounded bg-dark-600 border-dark-500 text-accent-500 focus:ring-accent-500" />
                                            <span className="text-sm">{ch}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>
                            <button className="bg-accent-500 hover:bg-accent-600 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors">
                                Save Configuration
                            </button>
                        </div>
                    </div>
                )}

                {activeTab === 'api' && (
                    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
                        <h2 className="text-lg font-semibold mb-4">API Documentation</h2>
                        <div className="space-y-4 font-mono text-sm">
                            {[
                                { method: 'GET', path: '/api/v1/health', desc: 'Health check' },
                                { method: 'GET', path: '/api/v1/cves?severity=critical&limit=10', desc: 'List CVEs with filters' },
                                { method: 'GET', path: '/api/v1/cves/{cve_id}', desc: 'Get CVE details with exploits' },
                                { method: 'GET', path: '/api/v1/stats/trends?days=30', desc: 'Get 30-day trends' },
                                { method: 'GET', path: '/api/v1/stats/severity-distribution', desc: 'Severity distribution' },
                                { method: 'POST', path: '/api/v1/alerts/configure', desc: 'Configure alerts' },
                            ].map((ep, i) => (
                                <div key={i} className="bg-dark-700 rounded-lg p-3 flex items-center gap-3">
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${ep.method === 'GET' ? 'bg-green-500/20 text-green-400' : 'bg-blue-500/20 text-blue-400'}`}>{ep.method}</span>
                                    <span className="text-accent-400">{ep.path}</span>
                                    <span className="text-gray-500 text-xs ml-auto">{ep.desc}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </main>

            {/* CVE Detail Modal */}
            {selectedCve && <CVEDetail cve={selectedCve} onClose={() => setSelectedCve(null)} />}
        </div>
    );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
