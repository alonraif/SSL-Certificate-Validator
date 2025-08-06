# SSL Certificate Validator

A comprehensive web-based SSL certificate validation tool that helps you verify certificates, check domains, and analyze certificate chains.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

### 🔐 Three Validation Modes

#### 1. **Certificate + Key Validation**
- Upload certificate and private key files
- Verify certificate/key matching
- Check certificate validity and expiration
- Optional domain verification
- Automatic certificate chain building
- Support for encrypted private keys

#### 2. **URL Certificate Check**
- Enter any HTTPS URL to fetch its certificate
- Live certificate validation from any website
- Custom port support (default: 443)
- Hostname verification
- Certificate chain analysis
- Download fetched certificates

#### 3. **Chain-Only Validation**
- Upload certificate chain files
- Verify correct certificate order (server → intermediate → root)
- Automatic chain reordering if needed
- Detect missing certificates
- Individual certificate validity checking
- Option to include/exclude root certificate

### 📊 Output Formats
- **PEM** - Certificate chain in PEM format
- **PDF** - Detailed validation report
- **JSON** - Machine-readable report for automation

### 🎨 User Experience
- Modern, responsive web interface
- Real-time validation feedback
- Drag-and-drop file upload
- Progress indicators for large files
- Dark theme with glassmorphism design

## Supported File Formats

- Certificate formats: `.pem`, `.der`, `.crt`, `.cer`, `.pfx`, `.p12`
- Private key formats: `.key`, `.pem`
- Maximum file size: 5MB

## Installation

### Local Development

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/ssl-certificate-validator.git
cd ssl-certificate-validator
```

2. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
python app.py
```

5. **Access the application**
Open your browser and navigate to `http://localhost:5000`

## Deployment

### Deploy on Render.com

1. **Fork or clone this repository to your GitHub account**

2. **Create a Render account** at [render.com](https://render.com)

3. **Create a new Web Service**
   - Connect your GitHub account
   - Select your repository
   - Use the following settings:
     - **Environment**: Python
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120`

4. **Deploy**
   - Click "Create Web Service"
   - Wait for the build to complete
   - Your app will be available at `https://your-app-name.onrender.com`

### Deploy on Other Platforms

The application can be deployed on any platform that supports Python web applications:

- **Heroku**: Add a `Procfile` with: `web: gunicorn app:app`
- **AWS Elastic Beanstalk**: Use the included `requirements.txt`
- **Google Cloud App Engine**: Add an `app.yaml` configuration
- **DigitalOcean App Platform**: Similar to Render configuration

## Usage Examples

### Validating a Certificate and Key

1. Click on the "Certificate + Key" tab
2. Upload your certificate file (e.g., `server.crt`)
3. Upload your private key file (e.g., `server.key`)
4. Enter key password if encrypted
5. Optionally enter a domain to verify
6. Click "Validate Certificate"
7. Download the validation report or fixed chain

### Checking a Website's Certificate

1. Click on the "URL Check" tab
2. Enter a URL (e.g., `example.com` or `https://example.com`)
3. Optionally specify a custom port (default: 443)
4. Click "Check Certificate"
5. View the certificate details and download the chain

### Fixing Certificate Chain Order

1. Click on the "Chain Only" tab
2. Upload a certificate chain file containing multiple certificates
3. Click "Validate Chain"
4. If the order is incorrect, download the fixed chain
5. Choose whether to include the root certificate

## API Endpoints

- `GET /` - Main application interface
- `POST /validate/cert-key` - Validate certificate and private key
- `POST /validate/url` - Check certificate from URL
- `POST /validate/chain` - Validate certificate chain order
- `GET /download/<file_type>` - Download generated files
- `GET /health` - Health check endpoint

## Configuration

### Environment Variables

- `SECRET_KEY` - Flask session secret key (auto-generated if not set)
- `PORT` - Server port (default: 5000)

### Application Settings

Edit these constants in `app.py`:

```python
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'.pem', '.der', '.crt', '.cer', '.key', '.pfx', '.p12'}
```

## Security Considerations

- All uploaded files are processed in memory and temporary files are automatically cleaned up
- No data is permanently stored on the server
- Sessions are used to maintain state between requests
- File uploads are limited to 5MB to prevent abuse
- Only specific file extensions are allowed

## Troubleshooting

### Common Issues

1. **"Both certificate and key files are required" error**
   - Ensure both files are selected before clicking validate
   - Check that files are not empty
   - Verify file formats are supported

2. **Certificate/key mismatch**
   - Ensure the private key corresponds to the certificate
   - Check if the private key is encrypted and provide the correct password

3. **URL connection errors**
   - Verify the URL is accessible
   - Check if you need to specify a custom port
   - Ensure the site uses HTTPS

4. **Chain order issues**
   - Upload the complete chain including all intermediate certificates
   - Use the "Download Fixed Chain" option to get the corrected order

### Debug Mode

For development, you can enable debug mode by modifying the last line of `app.py`:
```python
app.run(host='0.0.0.0', port=port, debug=True)
```

**Warning**: Never enable debug mode in production!

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Certificate handling via [cryptography](https://cryptography.io/)
- PDF generation using [FPDF](https://github.com/py-pdf/fpdf)
- UI styling with custom CSS and modern web standards

## Support

For issues, questions, or contributions, please:
- Open an issue on GitHub
- Submit a pull request
- Contact the maintainers

---

**Note**: This tool is for certificate validation and analysis only. Always ensure you're following security best practices when handling SSL certificates and private keys.
