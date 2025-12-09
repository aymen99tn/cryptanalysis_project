# TLS 1.3 Web Dashboard

Real-time monitoring dashboard for the TLS 1.3 Secure Document Server.

## Quick Start

```bash
# From project root
./scripts/start_dashboard.sh
```

Opens browser to: http://localhost:5000

## Features

- **Real-time Updates** - Server-Sent Events (SSE) for live data
- **Interactive Charts** - Chart.js visualizations
- **Dark Theme** - Professional and easy on eyes
- **Responsive Design** - Works on all devices
- **Multiple Panels**:
  - Status bar with uptime
  - Statistics cards
  - Recent requests table
  - Performance metrics with latency chart
  - Document popularity bar chart
  - TLS cipher distribution

## Requirements

```bash
pip3 install flask
```

## Architecture

### Backend (server.py)
- Python Flask web server
- Parses TLS server JSON logs
- Aggregates statistics
- Provides REST API
- SSE stream for real-time updates

### Frontend
- HTML5 + CSS3 + JavaScript
- Chart.js for visualizations
- Vanilla JavaScript (no frameworks)
- Real-time updates via SSE

### Data Flow

```
TLS Server → JSON Logs → Flask Backend → SSE/API → Browser
                              ↓
                         Statistics
                         Aggregation
```

## Directory Structure

```
dashboard/
├── server.py              # Flask backend
├── templates/
│   └── index.html        # Dashboard HTML
├── static/
│   ├── css/
│   │   └── dashboard.css # Stylesheet
│   └── js/
│       └── dashboard.js  # Frontend logic
└── README.md             # This file
```

## API Endpoints

### GET /
Main dashboard page

### GET /api/stats
Current statistics (JSON)

**Response Example:**
```json
{
  "status": "running",
  "uptime": 932.5,
  "total_connections": 47,
  "total_requests": 152,
  "total_errors": 0,
  "total_rate_limited": 2,
  "performance": {
    "avg_latency": 9.15,
    "min_latency": 6.2,
    "max_latency": 15.3,
    "rps": 53.2
  },
  "top_documents": [...],
  "cipher_distribution": [...],
  "recent_requests": [...]
}
```

### GET /api/events
Server-Sent Events (SSE) stream

**Event Types:**
- `connection` - New TLS connection
- `handshake` - TLS handshake complete
- `request` - Document request
- `error` - Error occurred
- `rate_limit` - Request rate limited

## Usage

### Auto-Start with Script
```bash
./scripts/start_dashboard.sh
```

### Manual Start
```bash
cd dashboard
python3 server.py
```

### Access Dashboard
```
http://localhost:5000
```

## Configuration

### Change Port
Edit `server.py`:
```python
app.run(host='0.0.0.0', port=5000, debug=False)
```

### Change Theme Colors
Edit `static/css/dashboard.css`:
```css
:root {
    --primary-color: #2196F3;
    --success-color: #4CAF50;
    /* ... */
}
```

### Modify Charts
Edit `static/js/dashboard.js`:
```javascript
// Chart options
const chartOptions = {
    responsive: true,
    // ...
};
```

## Development

### Enable Debug Mode
```python
app.run(debug=True)
```

### Test API Endpoints
```bash
# Get stats
curl http://localhost:5000/api/stats

# Monitor SSE
curl -N http://localhost:5000/api/events
```

### Browser DevTools
- Open console to see SSE messages
- Check network tab for API calls
- Inspect Chart.js canvas elements

## Troubleshooting

### Flask Not Installed
```bash
pip3 install flask
```

### Server Won't Start
```bash
# Check port 8080 (TLS server)
sudo netstat -tulpn | grep 8080

# Check port 5000 (dashboard)
sudo netstat -tulpn | grep 5000
```

### No Real-Time Updates
- Check browser console for SSE errors
- Verify firewall allows port 5000
- Fallback polling (2s interval) should still work

### Charts Not Showing
- Verify Chart.js CDN accessible
- Check browser console for errors
- Clear browser cache

## Performance

### Resource Usage
- Memory: ~50MB (Flask + Python)
- CPU: <1% (idle), ~5% (active)
- Network: Minimal (SSE stream)

### Scalability
- Handles 100+ requests/second
- Supports multiple concurrent viewers
- In-memory statistics (last 100 requests)

## Security

### Production Deployment
- Add authentication (Flask-Login)
- Use HTTPS (SSL/TLS)
- Set secure session keys
- Rate limit API endpoints
- Restrict allowed origins (CORS)

### Example: Add Basic Auth
```python
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Implement authentication
    return True

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')
```

## Integration

### Export Metrics
```bash
# Get JSON stats
curl http://localhost:5000/api/stats > metrics.json
```

### Forward Events
Edit `server.py` to forward events:
```python
def emit_event(event_type, data):
    # Existing code...

    # Forward to external system
    requests.post('http://monitoring/events', json=data)
```

### Database Storage
Add SQLite/Redis for historical data:
```python
import sqlite3

def store_request(data):
    conn = sqlite3.connect('metrics.db')
    # Store data...
```

## Browser Compatibility

- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile browsers
- ⚠️ IE11 (not supported)

## License

Educational/Research Use - University of New Brunswick

## Support

See main project documentation:
- `../docs/DASHBOARD_GUIDE.md` - Complete guide
- `../README.md` - Project overview
- `../QUICK_START.md` - Quick reference

---

**Made with ❤️ at University of New Brunswick**
