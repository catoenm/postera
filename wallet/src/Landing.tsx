import { Link } from 'react-router-dom'
import './Landing.css'

// Example ML-DSA-65 signature (3,309 bytes represented as hex, truncated for display)
const EXAMPLE_SIGNATURE = `8a4f2b1c9e7d3f5a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a
4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c
8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e
2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a
... (3,309 bytes total)`

// Example Groth16 ZK proof structure
const EXAMPLE_ZK_PROOF = {
  pi_a: [
    "12851273567193453827391087293847123984712398412",
    "98712348971234897123489712348971234897123489712",
    "1"
  ],
  pi_b: [
    ["28971234897123489712348971234897123489712348971", "12348971234897123489712348971234897123489712348"],
    ["89712348971234897123489712348971234897123489712", "34897123489712348971234897123489712348971234897"],
    ["1", "0"]
  ],
  pi_c: [
    "71234897123489712348971234897123489712348971234",
    "48971234897123489712348971234897123489712348971",
    "1"
  ],
  protocol: "groth16",
  curve: "bn128"
}

export default function Landing() {
  return (
    <div className="landing">
      <div className="landing-container">
        {/* Hero Section */}
        <header className="hero">
          <img src="/logo.png" alt="Postera" className="logo" />
          <h1 className="title">Postera</h1>
          <p className="tagline">The Future of Money is Quantum-Safe and Private</p>
          <nav className="nav-links hero-nav">
            <Link to="/wallet" className="nav-link">
              Open Wallet
            </Link>
            <Link to="/explorer" className="nav-link secondary">
              Block Explorer
            </Link>
          </nav>
        </header>

        {/* Description */}
        <section className="section">
          <h2>What is Postera?</h2>
          <p className="description">
            Postera is a privacy-focused cryptocurrency that combines <strong>post-quantum cryptography</strong> with
            <strong> zero-knowledge proofs</strong> to create truly private, quantum-resistant transactions.
          </p>
          <div className="features">
            <div className="feature">
              <div className="feature-icon">Q</div>
              <h3>Quantum Resistant</h3>
              <p>Built on ML-DSA-65 (CRYSTALS-Dilithium), a NIST-standardized lattice-based signature scheme that remains secure against quantum computers.</p>
            </div>
            <div className="feature">
              <div className="feature-icon">Z</div>
              <h3>Zero Knowledge</h3>
              <p>Shielded transactions use Groth16 ZK-SNARKs to prove validity without revealing sender, recipient, or amount.</p>
            </div>
            <div className="feature">
              <div className="feature-icon">P</div>
              <h3>Private by Default</h3>
              <p>All transaction amounts are hidden using Poseidon-based commitments. Only you can see your balance.</p>
            </div>
          </div>
        </section>

        {/* Quantum Signature Demo */}
        <section className="section">
          <h2>Quantum-Resistant Signatures</h2>
          <p className="section-intro">
            Every transaction is signed with <strong>ML-DSA-65</strong> (FIPS 204), a lattice-based digital signature
            algorithm standardized by NIST. Unlike ECDSA, it cannot be broken by Shor's algorithm.
          </p>
          <div className="demo-card">
            <div className="demo-header">
              <span className="demo-label">ML-DSA-65 Signature</span>
              <span className="demo-size">3,309 bytes</span>
            </div>
            <pre className="demo-content signature">{EXAMPLE_SIGNATURE}</pre>
            <div className="demo-footer">
              <div className="spec-item">
                <span className="spec-label">Public Key</span>
                <span className="spec-value">1,952 bytes</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Security Level</span>
                <span className="spec-value">NIST Level 3</span>
              </div>
            </div>
          </div>
        </section>

        {/* ZK Proof Demo */}
        <section className="section">
          <h2>Zero-Knowledge Proofs</h2>
          <p className="section-intro">
            Shielded transactions generate <strong>Groth16 proofs</strong> that cryptographically prove a transaction
            is valid without revealing any details. The proof is verified on-chain in constant time.
          </p>
          <div className="demo-card">
            <div className="demo-header">
              <span className="demo-label">Groth16 Spend Proof</span>
              <span className="demo-size">~200 bytes</span>
            </div>
            <pre className="demo-content proof">{JSON.stringify(EXAMPLE_ZK_PROOF, null, 2)}</pre>
            <div className="demo-footer">
              <div className="spec-item">
                <span className="spec-label">Curve</span>
                <span className="spec-value">BN254</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Hash Function</span>
                <span className="spec-value">Poseidon</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">Verification</span>
                <span className="spec-value">O(1)</span>
              </div>
            </div>
          </div>
        </section>

        {/* Whitepaper */}
        <section className="section whitepaper-section">
          <h2>Technical Details</h2>
          <p className="section-intro">
            For a complete technical specification of the protocol, cryptographic primitives,
            and security proofs, read the whitepaper.
          </p>
          <a href="/whitepaper.pdf" className="whitepaper-link" target="_blank" rel="noopener noreferrer">
            Download Whitepaper (PDF)
          </a>
          <p className="coming-soon">Coming Soon</p>
        </section>

        <footer className="footer">
          <p>MIT License</p>
        </footer>
      </div>
    </div>
  )
}
