import React from 'react';
import { useNavigate } from 'react-router-dom';

const scanCategories = [
  {
    title: 'Connection-Based Scans',
    scans: [
      { name: 'TCP Connect', description: 'Complete TCP three-way handshake' },
      { name: 'TCP SYN', description: 'Half-open SYN scan (stealth)' },
      { name: 'TCP FIN', description: 'FIN flag scan for firewall bypass' },
    ],
  },
  {
    title: 'Xmas & Flag-Based Scans',
    scans: [
      { name: 'TCP Xmas', description: 'FIN, PSH, URG flags set' },
      { name: 'TCP Null', description: 'No flags set' },
      { name: 'TCP ACK', description: 'ACK flag for firewall detection' },
    ],
  },
  {
    title: 'Advanced Scans',
    scans: [
      { name: 'TCP Window', description: 'Window size analysis' },
      { name: 'UDP', description: 'UDP port scanning' },
      { name: 'Idle', description: 'Zombie host stealth scan' },
    ],
  },
  {
    title: 'Host Discovery',
    scans: [
      { name: 'IP Protocol Scan', description: 'Detect supported IP protocols' },
      { name: 'OS-Detection', description: 'Guess OS using packet TTL' },
    ],
  },
];

function HomePage() {
  const navigate = useNavigate();
  return (
    <div className="home-page">
      <header className="App-header">
        <h1>IMPLEMENTATION OF PORT SCANNING TECHNIQUES</h1>
      </header>
      <div className="Contributors">
        <p>Carried out by:</p>
        <p>Anirudh S (231IT006)</p>
        <p>Siddharth K (231IT071)</p>
        <p>Srujan Swamy (231IT079)</p>
      </div>

      <div className="scan-categories">
        {scanCategories.map((category) => (
          <div key={category.title} className="category-section">
            <h2 className="category-title">{category.title}</h2>
            <div className="scan-grid">
              {category.scans.map((scan) => (
                <button
                  key={scan.name}
                  type="button"
                  onClick={() => navigate(`/scan/${scan.name}`)}
                  className="scan-card"
                >
                  <h3>{scan.name}</h3>
                  <p>{scan.description}</p>
                  <span className="arrow">→</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default HomePage;
