const endpoints = [
  ["GET", "/healthz", "Gateway health and mode"],
  ["GET", "/v1/version", "Gateway + upstream FHE version metadata"],
  ["GET", "/v1/fhe/public-key", "Active encryption key metadata"],
  ["POST", "/v1/telemetry/events", "Ciphertext ingest with idempotency"],
  ["POST", "/v1/fhe/evaluate", "Internal evaluate proxy route"],
  ["GET", "/v1/metrics", "Gateway + FHE Prometheus metrics"]
] as const;

export default function Page() {
  return (
    <main className="page">
      <header className="hero">
        <div className="hero-copy">
          <span className="pill">NINE65 v5 · Ciphertext-only gateway</span>
          <h1>Telemetry gateway is implemented and wired to Rust FHE.</h1>
          <p>
            This app persists encrypted telemetry in Postgres via Prisma,
            enforces idempotency, and forwards homomorphic evaluation to the
            Rust FHE service using <code>SecureConfig::secure_192()</code>.
          </p>
          <div className="hero-metrics">
            <div>
              <span className="metric-label">Security config</span>
              <span className="metric-value">secure_192</span>
            </div>
            <div>
              <span className="metric-label">Data handling</span>
              <span className="metric-value">Ciphertext only</span>
            </div>
            <div>
              <span className="metric-label">Status</span>
              <span className="metric-value">Pre-production</span>
            </div>
          </div>
        </div>
        <div className="hero-panel">
          <div className="panel-header">
            <span>Service Boundary</span>
            <span className="panel-tag">Node + Rust split</span>
          </div>
          <ul>
            <li>Node gateway validates auth, schema, and idempotency.</li>
            <li>Gateway stores telemetry ciphertext and metadata only.</li>
            <li>Rust service owns key metadata and FHE evaluation policy.</li>
            <li>Metrics endpoint merges gateway and FHE health signals.</li>
          </ul>
        </div>
      </header>

      <section className="grid">
        <article className="card">
          <h3>Implemented endpoints</h3>
          <div className="endpoint-list">
            {endpoints.map(([method, path, description]) => (
              <div key={path} className="endpoint-row">
                <span className="endpoint-method">{method}</span>
                <code className="endpoint-path">{path}</code>
                <span className="endpoint-description">{description}</span>
              </div>
            ))}
          </div>
        </article>
        <article className="card">
          <h3>Run locally</h3>
          <pre>
            <code>{`# terminal 1\ncd crates/fhe-service && cargo run --release\n\n# terminal 2\ncd apps/nine65-telemetry-gateway\ncp .env.example .env\nnpm install\nnpm run prisma:generate\nnpm run prisma:push\nnpm run dev`}</code>
          </pre>
        </article>
        <article className="card">
          <h3>Smoke test</h3>
          <pre>
            <code>{`python3 scripts/generate_telemetry.py --count 2 --output /tmp/events.jsonl\npython3 scripts/post_telemetry.py \\\n  --url http://127.0.0.1:3000/v1/telemetry/events \\\n  --input /tmp/events.jsonl \\\n  --bearer dev-token \\\n  --key-id fhekey_2026_02`}</code>
          </pre>
        </article>
      </section>
    </main>
  );
}
