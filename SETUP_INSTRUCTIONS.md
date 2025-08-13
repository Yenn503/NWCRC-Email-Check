# Email Breach Scanner - Setup Instructions

## Quick Start Guide

### 1. Get Your API Key
1. Visit [HaveIBeenPwned API Key page](https://haveibeenpwned.com/API/Key)
2. Purchase an API key (required for breach checking)
3. Copy your API key

### 2. Configure Your API Key
1. Open the `.env` file in the project root directory
2. Replace `your_api_key_here` with your actual API key:
   \`\`\`
   HIBP_API_KEY=your_actual_api_key_here
   \`\`\`
3. Save the file

### 3. Install Dependencies
\`\`\`bash
pip install -r requirements.txt
\`\`\`

### 4. Run the Application
\`\`\`bash
python app.py
\`\`\`

### 5. Access the Web Interface
Open your browser and go to: http://localhost:8000

## Configuration Options

### Environment Variables (.env file)
- `HIBP_API_KEY` - **REQUIRED** - Your HaveIBeenPwned API key
- `RATE_LIMIT_PER_MINUTE` - Optional (default: 10) - API requests per minute
- `FLASK_DEBUG` - Optional (default: True) - Enable debug mode
- `SECRET_KEY` - Optional - Flask secret key for sessions

### API Key Requirements
- The HaveIBeenPwned API requires a paid subscription
- Free tier is not available for automated tools
- Cost: ~$3.50 USD per month (as of 2024)
- Allows up to 10 requests per minute

## Troubleshooting

### "API key required" error
- Make sure you've set `HIBP_API_KEY` in your `.env` file
- Ensure there are no extra spaces around the API key
- Verify your API key is valid and active

### Rate limiting issues
- The API allows 10 requests per minute by default
- Large batches will be processed slowly to respect rate limits
- You can adjust `RATE_LIMIT_PER_MINUTE` if you have a higher tier plan

### File not found errors
- Make sure you're running the app from the project root directory
- Check that all required files are present

## Security Notes
- Never commit your `.env` file to version control
- Keep your API key secure and don't share it
- The `.env` file is already in `.gitignore` for protection
