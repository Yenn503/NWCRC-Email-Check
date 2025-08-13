# Email Breach Scanner

A professional web interface for checking email addresses against data breach databases using the HaveIBeenPwned API.

## Features

- **Single Email Scanning**: Quick breach check for individual email addresses
- **Batch Processing**: Scan up to 1000 emails with real-time progress tracking
- **Rate Limiting**: Respects API limits (10 requests per minute)
- **File Upload**: Support for .txt and .csv file uploads
- **Real-time Updates**: Live progress updates via WebSocket
- **Export Results**: Save results as JSON or CSV files
- **Professional UI**: Sleek design with midnight blue, black, and grey color scheme

## Setup

1) Install dependencies

```powershell
pip install -r requirements.txt
```

2) Configure environment

- Copy `.env.example` to `.env` and fill the values:

```
HIBP_API_KEY=your_hibp_api_key
SECRET_KEY=change_me
FLASK_DEBUG=false
RATE_LIMIT_PER_MINUTE=10
CHECK_PASTES=false
```

3) Run the app

```powershell
python app.py
```

4. **Access the Interface**:
   - Open your browser to `http://127.0.0.1:5000`

## Usage

### Single Email Scan
1. Enter an email address in the single scan section
2. Click "Scan Email" to check for breaches
3. View results immediately

### Batch Email Scan
1. Enter multiple emails (one per line) in the textarea
2. Or upload a .txt/.csv file with email addresses
3. Click "Start Batch Scan"
4. Monitor real-time progress with ETA
5. Export results (CSV, JSON, Excel, PDF, or ZIP) when complete

## API Rate Limiting & Performance

- Default: 10 requests/min (configurable via `RATE_LIMIT_PER_MINUTE` according to your HIBP plan)
- Paste checks can slow scans: set `CHECK_PASTES=false` for faster throughput
- Automatic handling of `429 Too Many Requests` via Retry-After

## File Structure

\`\`\`
email-breach-scanner/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Main HTML template
├── static/
│   ├── css/
│   │   └── style.css     # Styling
│   └── js/
│       └── app.js        # Frontend JavaScript
├── exports/              # Generated export files
└── uploads/              # Uploaded files (ignored)
\`\`\`

## Security Notes

- Keep your API key secure and never commit it to version control (.env is gitignored)
- The application runs locally for security
- All data processing happens on your machine
- No email addresses are stored permanently

## Troubleshooting

- **API Key Issues**: Ensure your HaveIBeenPwned API key is valid and set correctly
- **Rate Limiting**: The app automatically handles rate limits, but very large batches will take time
- **File Upload**: Ensure uploaded files contain valid email addresses (one per line for .txt, first column for .csv)
