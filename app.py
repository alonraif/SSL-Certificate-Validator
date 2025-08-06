import os
from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash, session, jsonify
import ssl
import tempfile
import hashlib
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from fpdf import FPDF
import urllib.request
import datetime
import socket
from urllib.parse import urlparse
import concurrent.futures
import logging
from io import BytesIO

app = Flask(__name__)

# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'.pem', '.der', '.crt', '.cer', '.key', '.pfx', '.p12'}
TEMP_FILE_PREFIX = 'ssl_validator_'

# Use system temp directory
TEMP_DIR = tempfile.gettempdir()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>SSL Certificate Validator & Analyzer</title>
    <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap' rel='stylesheet'>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(148, 163, 184, 0.1);
        }
        
        h1 {
            color: #38bdf8;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5rem;
            font-weight: 700;
        }
        
        .subtitle {
            text-align: center;
            color: #94a3b8;
            margin-bottom: 30px;
            font-size: 1.1rem;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #334155;
        }
        
        .tab {
            padding: 12px 24px;
            background: none;
            border: none;
            color: #94a3b8;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            position: relative;
            transition: all 0.3s ease;
            border-radius: 8px 8px 0 0;
        }
        
        .tab:hover {
            color: #cbd5e1;
            background: rgba(51, 65, 85, 0.3);
        }
        
        .tab.active {
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.1);
        }
        
        .tab.active::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            right: 0;
            height: 2px;
            background: #38bdf8;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #cbd5e1;
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            width: 100%;
        }
        
        input[type=file] {
            position: absolute;
            left: -9999px;
        }
        
        .file-input-label {
            display: block;
            padding: 14px;
            background: #334155;
            border: 2px dashed #475569;
            border-radius: 8px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            color: #94a3b8;
        }
        
        .file-input-label:hover {
            background: #3f4b63;
            border-color: #64748b;
            color: #cbd5e1;
        }
        
        .file-input-label.has-file {
            background: #1e3a5f;
            border-color: #38bdf8;
            color: #38bdf8;
        }
        
        input[type=password], input[type=text], input[type=url] {
            width: 100%;
            padding: 14px;
            background: #334155;
            border: 2px solid #475569;
            border-radius: 8px;
            color: #f1f5f9;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        input[type=password]:focus, input[type=text]:focus, input[type=url]:focus {
            outline: none;
            border-color: #38bdf8;
            background: #3f4b63;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 24px;
        }
        
        input[type=checkbox] {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            cursor: pointer;
        }
        
        .checkbox-group label {
            margin-bottom: 0;
            cursor: pointer;
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #38bdf8 0%, #0ea5e9 100%);
            color: #0f172a;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -5px rgba(56, 189, 248, 0.4);
        }
        
        .btn-primary:disabled {
            background: #475569;
            color: #94a3b8;
            cursor: not-allowed;
            transform: none;
        }
        
        .result-container {
            margin-top: 30px;
            padding: 24px;
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.2);
        }
        
        .result-success {
            border-color: #10b981;
            background: rgba(16, 185, 129, 0.1);
        }
        
        .result-error {
            border-color: #ef4444;
            background: rgba(239, 68, 68, 0.1);
        }
        
        .result-warning {
            border-color: #f59e0b;
            background: rgba(245, 158, 11, 0.1);
        }
        
        .result-header {
            display: flex;
            align-items: center;
            margin-bottom: 16px;
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .result-icon {
            margin-right: 10px;
            font-size: 1.5rem;
        }
        
        .result-details {
            white-space: pre-wrap;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            line-height: 1.6;
            color: #cbd5e1;
        }
        
        .download-links {
            display: flex;
            gap: 12px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .download-link {
            display: inline-flex;
            align-items: center;
            padding: 12px 20px;
            background: #1e40af;
            color: #fff;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .download-link:hover {
            background: #2563eb;
            transform: translateY(-2px);
        }
        
        .download-link svg {
            margin-right: 8px;
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 4px solid rgba(56, 189, 248, 0.2);
            border-radius: 50%;
            border-top-color: #38bdf8;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .flash-message {
            padding: 16px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-weight: 500;
            text-align: center;
            animation: slideIn 0.3s ease;
        }
        
        .flash-error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid #ef4444;
            color: #fca5a5;
        }
        
        .flash-success {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid #10b981;
            color: #86efac;
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(-20px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        .info-box {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 0.9rem;
            color: #93bbfe;
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }
        
        .feature-item {
            display: flex;
            align-items: center;
            color: #94a3b8;
            font-size: 0.9rem;
        }
        
        .feature-item svg {
            margin-right: 8px;
            color: #38bdf8;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid rgba(148, 163, 184, 0.1);
            color: #64748b;
            font-size: 0.875rem;
        }
        
        .url-example {
            font-size: 0.85rem;
            color: #64748b;
            margin-top: 4px;
        }
        
        .chain-order-info {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 0.85rem;
            color: #fbbf24;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>🔐 SSL Certificate Validator</h1>
        <p class='subtitle'>Validate certificates, check domains, and analyze chains</p>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class='flash-message flash-{{ category }}'>{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class='tabs'>
            <button class='tab active' onclick='switchTab("cert-key")'>Certificate + Key</button>
            <button class='tab' onclick='switchTab("url-check")'>URL Check</button>
            <button class='tab' onclick='switchTab("chain-only")'>Chain Only</button>
        </div>
        
        <!-- Certificate + Key Tab -->
        <div id='cert-key' class='tab-content active'>
            <div class='info-box'>
                <strong>Full validation:</strong> Upload certificate and private key for complete validation
                <div class='feature-grid'>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Key/cert matching
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Chain validation
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Domain verification
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        PDF reports
                    </div>
                </div>
            </div>
            
            <form method='post' action='/validate/cert-key' enctype='multipart/form-data' class='validateForm'>
                <div class='form-group'>
                    <label for='cert'>Certificate File</label>
                    <div class='file-input-wrapper'>
                        <input type='file' name='cert' id='cert' accept='.pem,.der,.crt,.cer,.pfx,.p12' required>
                        <label for='cert' class='file-input-label' id='certLabel'>
                            Choose certificate file...
                        </label>
                    </div>
                </div>
                
                <div class='form-group'>
                    <label for='key'>Private Key File</label>
                    <div class='file-input-wrapper'>
                        <input type='file' name='key' id='key' accept='.key,.pem' required>
                        <label for='key' class='file-input-label' id='keyLabel'>
                            Choose private key file...
                        </label>
                    </div>
                </div>
                
                <div class='form-group'>
                    <label for='key_password'>Private Key Password (if encrypted)</label>
                    <input type='password' name='key_password' id='key_password' placeholder='Leave empty if not encrypted'>
                </div>
                
                <div class='form-group'>
                    <label for='domain'>Domain to Verify (optional)</label>
                    <input type='text' name='domain' id='domain' placeholder='example.com'>
                </div>
                
                <div class='checkbox-group'>
                    <input type='checkbox' name='verify_chain' id='verify_chain' checked>
                    <label for='verify_chain'>Verify complete certificate chain</label>
                </div>
                
                <button type='submit' class='btn btn-primary submitBtn'>
                    Validate Certificate
                </button>
                
                <div class='loading'>
                    <div class='spinner'></div>
                    <p style='margin-top: 10px; color: #94a3b8;'>Validating certificate...</p>
                </div>
            </form>
        </div>
        
        <!-- URL Check Tab -->
        <div id='url-check' class='tab-content'>
            <div class='info-box'>
                <strong>URL certificate check:</strong> Verify the SSL certificate of any HTTPS website
                <div class='feature-grid'>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Live certificate fetch
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Chain verification
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Expiry checking
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Download chain
                    </div>
                </div>
            </div>
            
            <form method='post' action='/validate/url' class='validateForm'>
                <div class='form-group'>
                    <label for='url'>Website URL</label>
                    <input type='url' name='url' id='url' placeholder='https://example.com' required>
                    <p class='url-example'>Enter the full URL including https://</p>
                </div>
                
                <div class='form-group'>
                    <label for='port'>Port (optional)</label>
                    <input type='text' name='port' id='port' placeholder='443' pattern='[0-9]+'>
                    <p class='url-example'>Default: 443. Change for non-standard HTTPS ports</p>
                </div>
                
                <div class='checkbox-group'>
                    <input type='checkbox' name='check_hostname' id='check_hostname' checked>
                    <label for='check_hostname'>Verify hostname matches certificate</label>
                </div>
                
                <button type='submit' class='btn btn-primary submitBtn'>
                    Check Certificate
                </button>
                
                <div class='loading'>
                    <div class='spinner'></div>
                    <p style='margin-top: 10px; color: #94a3b8;'>Fetching certificate...</p>
                </div>
            </form>
        </div>
        
        <!-- Chain Only Tab -->
        <div id='chain-only' class='tab-content'>
            <div class='info-box'>
                <strong>Chain validation:</strong> Upload a certificate chain to verify order and completeness
                <div class='feature-grid'>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Order verification
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Auto-fix chain order
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Missing cert detection
                    </div>
                    <div class='feature-item'>
                        <svg width='16' height='16' fill='currentColor' viewBox='0 0 16 16'>
                            <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        </svg>
                        Download fixed chain
                    </div>
                </div>
            </div>
            
            <form method='post' action='/validate/chain' enctype='multipart/form-data' class='validateForm'>
                <div class='chain-order-info'>
                    <strong>Note:</strong> Upload a file containing the full certificate chain. The validator will check if certificates are in the correct order (server → intermediate → root) and offer to fix any issues.
                </div>
                
                <div class='form-group'>
                    <label for='chain_file'>Certificate Chain File</label>
                    <div class='file-input-wrapper'>
                        <input type='file' name='chain_file' id='chain_file' accept='.pem,.crt,.cer' required>
                        <label for='chain_file' class='file-input-label' id='chainLabel'>
                            Choose certificate chain file...
                        </label>
                    </div>
                </div>
                
                <div class='checkbox-group'>
                    <input type='checkbox' name='include_root' id='include_root'>
                    <label for='include_root'>Include root certificate in output (not recommended for servers)</label>
                </div>
                
                <button type='submit' class='btn btn-primary submitBtn'>
                    Validate Chain
                </button>
                
                <div class='loading'>
                    <div class='spinner'></div>
                    <p style='margin-top: 10px; color: #94a3b8;'>Analyzing certificate chain...</p>
                </div>
            </form>
        </div>
        
        {% if result %}
        <div class='result-container result-{{ result_type }}'>
            <div class='result-header'>
                <span class='result-icon'>
                    {% if result_type == 'success' %}✅{% elif result_type == 'error' %}❌{% else %}⚠️{% endif %}
                </span>
                Validation Result
            </div>
            <div class='result-details'>{{ result }}</div>
            
            {% if download_links %}
            <div class='download-links'>
                {% if 'chain' in download_links %}
                <a href='{{ download_links.chain }}' class='download-link'>
                    <svg width='20' height='20' fill='currentColor' viewBox='0 0 16 16'>
                        <path d='M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z'/>
                        <path d='M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z'/>
                    </svg>
                    Download Certificate Chain
                </a>
                {% endif %}
                {% if 'fixed_chain' in download_links %}
                <a href='{{ download_links.fixed_chain }}' class='download-link' style='background: #10b981;'>
                    <svg width='20' height='20' fill='currentColor' viewBox='0 0 16 16'>
                        <path d='M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z'/>
                        <path d='M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z'/>
                    </svg>
                    Download Fixed Chain
                </a>
                {% endif %}
                {% if 'report' in download_links %}
                <a href='{{ download_links.report }}' class='download-link'>
                    <svg width='20' height='20' fill='currentColor' viewBox='0 0 16 16'>
                        <path d='M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5L14 4.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5h-2z'/>
                    </svg>
                    Download PDF Report
                </a>
                {% endif %}
                {% if 'json' in download_links %}
                <a href='{{ download_links.json }}' class='download-link'>
                    <svg width='20' height='20' fill='currentColor' viewBox='0 0 16 16'>
                        <path d='M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5L14 4.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5h-2z'/>
                        <path d='M4.5 12.5A.5.5 0 0 1 5 12h3a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zm0-2A.5.5 0 0 1 5 10h6a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zm1.639-3.708 1.33.886 1.854-1.855a.25.25 0 0 1 .289-.047l1.888.974V8.5a.5.5 0 0 1-.5.5H5a.5.5 0 0 1-.5-.5V8s1.54-1.274 1.639-1.208zM6.25 6a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5z'/>
                    </svg>
                    Download JSON Report
                </a>
                {% endif %}
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <div class='footer'>
            <p>SSL Certificate Validator - Secure validation for your certificates</p>
        </div>
    </div>
    
    <script>
        // Tab switching
        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tabName).classList.add('active');
        }
        
        // File input handling
        document.getElementById('cert')?.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Choose certificate file...';
            const label = document.getElementById('certLabel');
            label.textContent = fileName;
            label.classList.toggle('has-file', e.target.files.length > 0);
        });
        
        document.getElementById('key')?.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Choose private key file...';
            const label = document.getElementById('keyLabel');
            label.textContent = fileName;
            label.classList.toggle('has-file', e.target.files.length > 0);
        });
        
        document.getElementById('chain_file')?.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Choose certificate chain file...';
            const label = document.getElementById('chainLabel');
            label.textContent = fileName;
            label.classList.toggle('has-file', e.target.files.length > 0);
        });
        
        // Form validation
        document.querySelectorAll('.validateForm').forEach(form => {
            form.addEventListener('submit', function(e) {
                const submitBtn = this.querySelector('.submitBtn');
                const loading = this.querySelector('.loading');
                
                // Show loading state
                loading.style.display = 'block';
                submitBtn.disabled = true;
                submitBtn.textContent = 'Processing...';
            });
        });
        
        // Domain input validation
        document.getElementById('domain')?.addEventListener('input', function(e) {
            const value = e.target.value;
            const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$/;
            if (value && !domainPattern.test(value)) {
                e.target.style.borderColor = '#ef4444';
            } else {
                e.target.style.borderColor = '#475569';
            }
        });
        
        // Port validation
        document.getElementById('port')?.addEventListener('input', function(e) {
            const value = e.target.value;
            const port = parseInt(value);
            if (value && (isNaN(port) || port < 1 || port > 65535)) {
                e.target.style.borderColor = '#ef4444';
            } else {
                e.target.style.borderColor = '#475569';
            }
        });
        
        // Restore active tab if result is present
        {% if active_tab %}
        switchTab('{{ active_tab }}');
        document.querySelector('.tab.active').classList.remove('active');
        document.querySelector('.tab[onclick*="{{ active_tab }}"]').classList.add('active');
        {% endif %}
    </script>
</body>
</html>
'''

class CertificateValidator:
    def __init__(self):
        self.temp_files = []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
    
    def cleanup(self):
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                logger.error(f"Failed to cleanup temp file {temp_file}: {e}")
    
    def create_temp_file(self, data, suffix=''):
        temp_file = tempfile.NamedTemporaryFile(
            prefix=TEMP_FILE_PREFIX,
            suffix=suffix,
            delete=False,
            dir=TEMP_DIR
        )
        temp_file.write(data)
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    def load_certificate(self, cert_data):
        """Load certificate from PEM or DER format"""
        try:
            if cert_data.strip().startswith(b'-----BEGIN'):
                return x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                return x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception as e:
            raise ValueError(f"Failed to load certificate: {str(e)}")
    
    def load_certificate_chain(self, chain_data):
        """Load multiple certificates from a chain file"""
        certificates = []
        
        # Handle PEM format
        if b'-----BEGIN' in chain_data:
            # Split by certificate boundaries
            cert_starts = chain_data.split(b'-----BEGIN CERTIFICATE-----')
            for cert_start in cert_starts[1:]:  # Skip first empty element
                try:
                    cert_data = b'-----BEGIN CERTIFICATE-----' + cert_start.split(b'-----END CERTIFICATE-----')[0] + b'-----END CERTIFICATE-----'
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    certificates.append(cert)
                except Exception as e:
                    logger.warning(f"Failed to load certificate from chain: {e}")
        else:
            # Try DER format (single certificate)
            try:
                cert = x509.load_der_x509_certificate(chain_data, default_backend())
                certificates.append(cert)
            except Exception as e:
                raise ValueError(f"Failed to load certificate chain: {str(e)}")
        
        return certificates
    
    def get_url_certificate(self, url, port=443, timeout=10):
        """Fetch certificate from URL"""
        # Parse URL
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        
        # Remove any path components if no scheme was provided
        if not parsed.hostname and '/' in hostname:
            hostname = hostname.split('/')[0]
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get the certificate in DER format
                    der_cert = ssock.getpeercert(True)
                    # Get the full peer certificate chain
                    peer_cert_chain = ssock.getpeercert_chain()
                    
                    # Convert to x509 objects
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Get full chain if available
                    chain = []
                    if peer_cert_chain:
                        for cert_der in peer_cert_chain:
                            try:
                                chain_cert = x509.load_der_x509_certificate(cert_der, default_backend())
                                chain.append(chain_cert)
                            except:
                                pass
                    
                    return cert, chain, hostname
                    
        except socket.timeout:
            raise ValueError(f"Connection to {hostname}:{port} timed out")
        except socket.gaierror:
            raise ValueError(f"Failed to resolve hostname: {hostname}")
        except Exception as e:
            raise ValueError(f"Failed to connect to {hostname}:{port}: {str(e)}")
    
    def verify_certificate_chain_order(self, certificates):
        """Verify if certificates are in correct order and find the correct order"""
        if not certificates:
            return False, [], "No certificates provided"
        
        if len(certificates) == 1:
            return True, certificates, "Single certificate (no chain to verify)"
        
        # Build a map of subject -> certificate
        subject_to_cert = {}
        issuer_to_certs = {}
        
        for cert in certificates:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            subject_to_cert[subject] = cert
            
            if issuer not in issuer_to_certs:
                issuer_to_certs[issuer] = []
            issuer_to_certs[issuer].append(cert)
        
        # Find the end-entity certificate (leaf)
        # It should have an issuer that is the subject of another cert, but no cert has it as issuer
        leaf_certs = []
        for cert in certificates:
            subject = cert.subject.rfc4514_string()
            # Check if this cert is an issuer for any other cert
            is_issuer = any(c.issuer.rfc4514_string() == subject for c in certificates if c != cert)
            
            # Check if it's likely a CA cert
            try:
                basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                is_ca = basic_constraints.value.ca
            except:
                is_ca = False
            
            if not is_issuer and not is_ca:
                leaf_certs.append(cert)
        
        if not leaf_certs:
            # If no clear leaf, pick the cert that's not a CA
            for cert in certificates:
                try:
                    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                    if not basic_constraints.value.ca:
                        leaf_certs.append(cert)
                except:
                    leaf_certs.append(cert)
        
        if not leaf_certs:
            return False, certificates, "Could not identify leaf certificate"
        
        # Build the chain starting from the leaf
        correct_order = []
        current = leaf_certs[0]
        used_certs = set()
        
        while current:
            correct_order.append(current)
            used_certs.add(current)
            
            # Find the issuer
            issuer_name = current.issuer.rfc4514_string()
            next_cert = None
            
            # Look for exact subject match
            if issuer_name in subject_to_cert and subject_to_cert[issuer_name] not in used_certs:
                next_cert = subject_to_cert[issuer_name]
            
            # If self-signed, we've reached the root
            if current.subject == current.issuer:
                break
            
            current = next_cert
        
        # Add any remaining certificates (might be alternate chains or roots)
        for cert in certificates:
            if cert not in used_certs:
                correct_order.append(cert)
        
        # Check if the original order matches the correct order
        is_correct = len(correct_order) == len(certificates)
        if is_correct:
            for i, cert in enumerate(certificates):
                if cert != correct_order[i]:
                    is_correct = False
                    break
        
        return is_correct, correct_order, "Chain order verified"
    
    def load_private_key(self, key_data, password=None):
        """Load private key with optional password"""
        try:
            return serialization.load_pem_private_key(
                key_data, 
                password=password, 
                backend=default_backend()
            )
        except Exception:
            # Try DER format
            return serialization.load_der_private_key(
                key_data, 
                password=password, 
                backend=default_backend()
            )
    
    def fetch_intermediate_certificates(self, cert):
        """Fetch intermediate certificates from AIA extension"""
        chain = []
        seen_urls = set()
        current_cert = cert
        
        while current_cert:
            try:
                aia_ext = current_cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                
                ca_issuer_url = None
                for desc in aia_ext.value:
                    if desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                        ca_issuer_url = desc.access_location.value
                        break
                
                if not ca_issuer_url or ca_issuer_url in seen_urls:
                    break
                
                seen_urls.add(ca_issuer_url)
                
                # Fetch certificate with timeout
                with urllib.request.urlopen(ca_issuer_url, timeout=10) as response:
                    cert_data = response.read()
                    intermediate_cert = self.load_certificate(cert_data)
                    chain.append(intermediate_cert)
                    current_cert = intermediate_cert
                    
            except Exception as e:
                logger.warning(f"Failed to fetch intermediate certificate: {e}")
                break
        
        return chain
    
    def build_certificate_chain(self, cert):
        """Build complete certificate chain"""
        chain = [cert]
        intermediates = self.fetch_intermediate_certificates(cert)
        chain.extend(intermediates)
        return chain
    
    def extract_certificate_info(self, cert):
        """Extract detailed certificate information"""
        info = {
            'subject': {},
            'issuer': {},
            'san': [],
            'serial_number': format(cert.serial_number, 'x'),
            'not_before': cert.not_valid_before,
            'not_after': cert.not_valid_after,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'version': cert.version.name,
            'is_ca': False,
            'key_usage': [],
            'extended_key_usage': []
        }
        
        # Extract subject
        for attr in cert.subject:
            info['subject'][attr.oid._name] = attr.value
        
        # Extract issuer
        for attr in cert.issuer:
            info['issuer'][attr.oid._name] = attr.value
        
        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info['san'] = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        # Check if CA certificate
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            info['is_ca'] = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass
        
        # Extract key usage
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage_attrs = ['digital_signature', 'content_commitment', 'key_encipherment',
                          'data_encipherment', 'key_agreement', 'key_cert_sign',
                          'crl_sign']
            
            # Check basic attributes
            for attr in usage_attrs:
                if hasattr(key_usage.value, attr) and getattr(key_usage.value, attr):
                    info['key_usage'].append(attr)
            
            # encipher_only and decipher_only are only valid when key_agreement is true
            if hasattr(key_usage.value, 'key_agreement') and key_usage.value.key_agreement:
                if hasattr(key_usage.value, 'encipher_only') and key_usage.value.encipher_only:
                    info['key_usage'].append('encipher_only')
                if hasattr(key_usage.value, 'decipher_only') and key_usage.value.decipher_only:
                    info['key_usage'].append('decipher_only')
                    
        except x509.ExtensionNotFound:
            pass
        
        # Extract extended key usage
        try:
            ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            info['extended_key_usage'] = [usage._name for usage in ext_key_usage.value]
        except x509.ExtensionNotFound:
            pass
        
        return info
    
    def verify_domain_match(self, cert, domain):
        """Verify if domain matches certificate"""
        if not domain:
            return True, "No domain specified for verification"
        
        # Get certificate domains
        cert_domains = []
        
        # Add CN from subject
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            cert_domains.append(cn)
        except:
            pass
        
        # Add SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    cert_domains.append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        # Check domain match
        domain_lower = domain.lower()
        for cert_domain in cert_domains:
            cert_domain_lower = cert_domain.lower()
            if cert_domain_lower == domain_lower:
                return True, f"Domain '{domain}' matches certificate"
            
            # Check wildcard
            if cert_domain_lower.startswith('*.'):
                wildcard_domain = cert_domain_lower[2:]
                if domain_lower.endswith(wildcard_domain):
                    # Check that it's a direct subdomain
                    prefix = domain_lower[:-len(wildcard_domain)]
                    if '.' not in prefix.rstrip('.'):
                        return True, f"Domain '{domain}' matches wildcard certificate"
        
        return False, f"Domain '{domain}' does not match certificate. Certificate domains: {', '.join(cert_domains)}"
    
    def generate_pdf_report(self, cert_info, chain_info, validation_results, output_path):
        """Generate detailed PDF report"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", size=16)
        pdf.cell(0, 10, "SSL Certificate Validation Report", ln=True, align='C')
        pdf.ln(5)
        
        # Report metadata
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 10, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
        pdf.ln(5)
        
        # Certificate information
        pdf.set_font("Arial", "B", size=14)
        pdf.cell(0, 10, "Certificate Information", ln=True)
        pdf.set_font("Arial", size=10)
        
        # Subject
        pdf.cell(0, 6, f"Subject:", ln=True)
        for key, value in cert_info['subject'].items():
            pdf.cell(10)
            pdf.cell(0, 6, f"{key}: {value}", ln=True)
        
        pdf.ln(3)
        
        # Issuer
        pdf.cell(0, 6, f"Issuer:", ln=True)
        for key, value in cert_info['issuer'].items():
            pdf.cell(10)
            pdf.cell(0, 6, f"{key}: {value}", ln=True)
        
        pdf.ln(3)
        
        # Validity
        pdf.cell(0, 6, f"Valid From: {cert_info['not_before']}", ln=True)
        pdf.cell(0, 6, f"Valid Until: {cert_info['not_after']}", ln=True)
        pdf.cell(0, 6, f"Serial Number: {cert_info['serial_number']}", ln=True)
        pdf.cell(0, 6, f"Signature Algorithm: {cert_info['signature_algorithm']}", ln=True)
        
        pdf.ln(3)
        
        # SANs
        if cert_info['san']:
            pdf.cell(0, 6, f"Subject Alternative Names:", ln=True)
            for san in cert_info['san']:
                pdf.cell(10)
                pdf.cell(0, 6, f"- {san}", ln=True)
        
        # Chain information
        if chain_info:
            pdf.add_page()
            pdf.set_font("Arial", "B", size=14)
            pdf.cell(0, 10, "Certificate Chain", ln=True)
            pdf.set_font("Arial", size=10)
            
            for i, cert in enumerate(chain_info):
                pdf.cell(0, 6, f"{i+1}. {cert['subject'].get('commonName', 'Unknown')}", ln=True)
                pdf.cell(10)
                pdf.cell(0, 6, f"Issuer: {cert['issuer'].get('commonName', 'Unknown')}", ln=True)
                pdf.ln(2)
        
        # Validation results
        pdf.add_page()
        pdf.set_font("Arial", "B", size=14)
        pdf.cell(0, 10, "Validation Results", ln=True)
        pdf.set_font("Arial", size=10)
        
        for result in validation_results:
            status = "PASS" if result['status'] else "FAIL"
            pdf.cell(0, 6, f"[{status}] {result['check']}: {result['message']}", ln=True)
        
        pdf.output(output_path)
    
    def generate_json_report(self, cert_info, chain_info, validation_results, output_path):
        """Generate JSON report"""
        report = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'certificate': cert_info,
            'chain': chain_info,
            'validation_results': validation_results
        }
        
        import json
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

@app.route('/')
def index():
    result = session.pop('result', None)
    result_type = session.pop('result_type', None)
    download_links = session.pop('download_links', None)
    active_tab = session.pop('active_tab', None)
    return render_template_string(HTML_TEMPLATE, 
                                result=result, 
                                result_type=result_type,
                                download_links=download_links,
                                active_tab=active_tab)

@app.route('/validate/cert-key', methods=['POST'])
def validate_cert_key():
    """Original certificate + key validation"""
    validator = CertificateValidator()
    
    try:
        # Get uploaded files
        cert_file = request.files.get('cert')
        key_file = request.files.get('key')
        
        if not cert_file or not key_file:
            flash('Both certificate and key files are required.', 'error')
            return redirect(url_for('index'))
        
        # Validate file extensions
        cert_ext = os.path.splitext(cert_file.filename)[1].lower()
        key_ext = os.path.splitext(key_file.filename)[1].lower()
        
        if cert_ext not in ALLOWED_EXTENSIONS:
            flash(f'Invalid certificate file type: {cert_ext}', 'error')
            return redirect(url_for('index'))
        
        # Read file data
        cert_data = cert_file.read()
        key_data = key_file.read()
        
        # Validate file sizes
        if len(cert_data) > MAX_FILE_SIZE or len(key_data) > MAX_FILE_SIZE:
            flash('File size exceeds maximum allowed (5MB).', 'error')
            return redirect(url_for('index'))
        
        # Get optional parameters
        key_password = request.form.get('key_password', '').encode() or None
        domain = request.form.get('domain', '').strip()
        verify_chain = request.form.get('verify_chain', 'on') == 'on'
        
        # Load certificate
        cert = validator.load_certificate(cert_data)
        
        # Load private key
        try:
            private_key = validator.load_private_key(key_data, key_password)
        except Exception as e:
            session['result'] = f"Private key error: {str(e)}"
            session['result_type'] = 'error'
            session['active_tab'] = 'cert-key'
            return redirect(url_for('index'))
        
        # Extract certificate information
        cert_info = validator.extract_certificate_info(cert)
        
        # Build certificate chain
        if verify_chain:
            chain = validator.build_certificate_chain(cert)
        else:
            chain = [cert]
        
        # Create chain PEM
        chain_pem = b''
        for cert_in_chain in chain:
            chain_pem += cert_in_chain.public_bytes(serialization.Encoding.PEM)
        
        # Validate certificate/key pair
        validation_results = []
        
        # Check if certificate and key match
        cert_path = validator.create_temp_file(chain_pem, '.pem')
        key_path = validator.create_temp_file(key_data, '.key')
        
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path, 
                                  password=key_password.decode() if key_password else None)
            validation_results.append({
                'check': 'Certificate/Key Match',
                'status': True,
                'message': 'Certificate and private key match'
            })
        except Exception as e:
            validation_results.append({
                'check': 'Certificate/Key Match',
                'status': False,
                'message': str(e)
            })
            session['result'] = f"Certificate/key validation failed: {str(e)}"
            session['result_type'] = 'error'
            session['active_tab'] = 'cert-key'
            return redirect(url_for('index'))
        
        # Check certificate validity period
        now = datetime.datetime.utcnow()
        if now < cert_info['not_before']:
            validation_results.append({
                'check': 'Validity Period',
                'status': False,
                'message': f"Certificate not yet valid (starts {cert_info['not_before']})"
            })
        elif now > cert_info['not_after']:
            validation_results.append({
                'check': 'Validity Period',
                'status': False,
                'message': f"Certificate has expired ({cert_info['not_after']})"
            })
        else:
            days_until_expiry = (cert_info['not_after'] - now).days
            validation_results.append({
                'check': 'Validity Period',
                'status': True,
                'message': f"Certificate is valid ({days_until_expiry} days until expiry)"
            })
        
        # Check domain match
        if domain:
            domain_match, domain_message = validator.verify_domain_match(cert, domain)
            validation_results.append({
                'check': 'Domain Verification',
                'status': domain_match,
                'message': domain_message
            })
        
        # Check certificate chain
        if verify_chain and len(chain) > 1:
            validation_results.append({
                'check': 'Certificate Chain',
                'status': True,
                'message': f"Complete chain built ({len(chain)} certificates)"
            })
        elif verify_chain:
            validation_results.append({
                'check': 'Certificate Chain',
                'status': False,
                'message': "Could not build complete certificate chain"
            })
        
        # Prepare result summary
        result_lines = ["Certificate Validation Report\n" + "="*40 + "\n"]
        
        # Certificate details
        result_lines.append(f"Subject: {cert_info['subject'].get('commonName', 'N/A')}")
        result_lines.append(f"Issuer: {cert_info['issuer'].get('commonName', 'N/A')}")
        if cert_info['san']:
            result_lines.append(f"SANs: {', '.join(cert_info['san'][:5])}")
            if len(cert_info['san']) > 5:
                result_lines.append(f"      ... and {len(cert_info['san']) - 5} more")
        result_lines.append(f"Valid From: {cert_info['not_before']}")
        result_lines.append(f"Valid Until: {cert_info['not_after']}")
        result_lines.append(f"Serial Number: {cert_info['serial_number']}")
        result_lines.append("")
        
        # Validation results
        result_lines.append("Validation Results:")
        for result in validation_results:
            status = "✅" if result['status'] else "❌"
            result_lines.append(f"{status} {result['check']}: {result['message']}")
        
        # Determine overall result type
        if all(r['status'] for r in validation_results):
            result_type = 'success'
        elif any(not r['status'] for r in validation_results):
            result_type = 'warning' if any(r['status'] for r in validation_results) else 'error'
        
        # Save files for download
        session_id = session.get('_id', 'default')
        chain_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}chain_{session_id}.pem")
        with open(chain_path, 'wb') as f:
            f.write(chain_pem)
        
        # Generate reports
        report_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.pdf")
        chain_info = [validator.extract_certificate_info(c) for c in chain]
        validator.generate_pdf_report(cert_info, chain_info, validation_results, report_path)
        
        json_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.json")
        validator.generate_json_report(cert_info, chain_info, validation_results, json_path)
        
        # Set session data
        session['result'] = '\n'.join(result_lines)
        session['result_type'] = result_type
        session['download_links'] = {
            'chain': '/download/chain',
            'report': '/download/report',
            'json': '/download/json'
        }
        session['active_tab'] = 'cert-key'
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        session['result'] = f"Validation error: {str(e)}"
        session['result_type'] = 'error'
        session['active_tab'] = 'cert-key'
    finally:
        validator.cleanup()
    
    return redirect(url_for('index'))

@app.route('/validate/url', methods=['POST'])
def validate_url():
    """Validate certificate from URL"""
    validator = CertificateValidator()
    
    try:
        # Get form data
        url = request.form.get('url', '').strip()
        port = request.form.get('port', '443').strip()
        check_hostname = request.form.get('check_hostname', 'on') == 'on'
        
        if not url:
            flash('Please enter a URL.', 'error')
            return redirect(url_for('index'))
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate port
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError
        except:
            flash('Invalid port number. Please enter a number between 1 and 65535.', 'error')
            return redirect(url_for('index'))
        
        # Fetch certificate from URL
        cert, chain, hostname = validator.get_url_certificate(url, port)
        
        # Extract certificate information
        cert_info = validator.extract_certificate_info(cert)
        
        # If no chain was provided by server, try to build it
        if not chain or len(chain) == 1:
            chain = validator.build_certificate_chain(cert)
        
        # Validation results
        validation_results = []
        
        # Check certificate validity period
        now = datetime.datetime.utcnow()
        if now < cert_info['not_before']:
            validation_results.append({
                'check': 'Validity Period',
                'status': False,
                'message': f"Certificate not yet valid (starts {cert_info['not_before']})"
            })
        elif now > cert_info['not_after']:
            validation_results.append({
                'check': 'Validity Period',
                'status': False,
                'message': f"Certificate has expired ({cert_info['not_after']})"
            })
        else:
            days_until_expiry = (cert_info['not_after'] - now).days
            validation_results.append({
                'check': 'Validity Period',
                'status': True,
                'message': f"Certificate is valid ({days_until_expiry} days until expiry)"
            })
        
        # Check hostname match
        if check_hostname:
            domain_match, domain_message = validator.verify_domain_match(cert, hostname)
            validation_results.append({
                'check': 'Hostname Verification',
                'status': domain_match,
                'message': domain_message
            })
        
        # Check certificate chain
        if len(chain) > 1:
            validation_results.append({
                'check': 'Certificate Chain',
                'status': True,
                'message': f"Certificate chain contains {len(chain)} certificates"
            })
            
            # Verify chain order
            is_correct, _, order_message = validator.verify_certificate_chain_order(chain)
            validation_results.append({
                'check': 'Chain Order',
                'status': is_correct,
                'message': order_message if is_correct else "Chain may not be in correct order"
            })
        else:
            validation_results.append({
                'check': 'Certificate Chain',
                'status': False,
                'message': "Only single certificate found (no chain)"
            })
        
        # Prepare result summary
        result_lines = [f"Certificate Report for {hostname}:{port}\n" + "="*40 + "\n"]
        
        # Certificate details
        result_lines.append(f"Subject: {cert_info['subject'].get('commonName', 'N/A')}")
        result_lines.append(f"Issuer: {cert_info['issuer'].get('commonName', 'N/A')}")
        if cert_info['san']:
            result_lines.append(f"SANs: {', '.join(cert_info['san'][:5])}")
            if len(cert_info['san']) > 5:
                result_lines.append(f"      ... and {len(cert_info['san']) - 5} more")
        result_lines.append(f"Valid From: {cert_info['not_before']}")
        result_lines.append(f"Valid Until: {cert_info['not_after']}")
        result_lines.append(f"Serial Number: {cert_info['serial_number']}")
        result_lines.append("")
        
        # Validation results
        result_lines.append("Validation Results:")
        for result in validation_results:
            status = "✅" if result['status'] else "❌"
            result_lines.append(f"{status} {result['check']}: {result['message']}")
        
        # Determine overall result type
        if all(r['status'] for r in validation_results):
            result_type = 'success'
        elif any(not r['status'] for r in validation_results):
            result_type = 'warning' if any(r['status'] for r in validation_results) else 'error'
        
        # Create chain PEM
        chain_pem = b''
        for cert_in_chain in chain:
            chain_pem += cert_in_chain.public_bytes(serialization.Encoding.PEM)
        
        # Save files for download
        session_id = session.get('_id', 'default')
        chain_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}chain_{session_id}.pem")
        with open(chain_path, 'wb') as f:
            f.write(chain_pem)
        
        # Generate reports
        report_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.pdf")
        chain_info = [validator.extract_certificate_info(c) for c in chain]
        validator.generate_pdf_report(cert_info, chain_info, validation_results, report_path)
        
        json_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.json")
        validator.generate_json_report(cert_info, chain_info, validation_results, json_path)
        
        # Set session data
        session['result'] = '\n'.join(result_lines)
        session['result_type'] = result_type
        session['download_links'] = {
            'chain': '/download/chain',
            'report': '/download/report',
            'json': '/download/json'
        }
        session['active_tab'] = 'url-check'
        
    except Exception as e:
        logger.error(f"URL validation error: {str(e)}", exc_info=True)
        session['result'] = f"Error fetching certificate: {str(e)}"
        session['result_type'] = 'error'
        session['active_tab'] = 'url-check'
    finally:
        validator.cleanup()
    
    return redirect(url_for('index'))

@app.route('/validate/chain', methods=['POST'])
def validate_chain_only():
    """Validate certificate chain order and completeness"""
    validator = CertificateValidator()
    
    try:
        # Get uploaded file
        chain_file = request.files.get('chain_file')
        
        if not chain_file:
            flash('Please upload a certificate chain file.', 'error')
            return redirect(url_for('index'))
        
        # Validate file extension
        file_ext = os.path.splitext(chain_file.filename)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            flash(f'Invalid file type: {file_ext}', 'error')
            return redirect(url_for('index'))
        
        # Read file data
        chain_data = chain_file.read()
        
        # Validate file size
        if len(chain_data) > MAX_FILE_SIZE:
            flash('File size exceeds maximum allowed (5MB).', 'error')
            return redirect(url_for('index'))
        
        # Get options
        include_root = request.form.get('include_root', 'off') == 'on'
        
        # Load certificates from chain
        certificates = validator.load_certificate_chain(chain_data)
        
        if not certificates:
            session['result'] = "No valid certificates found in the uploaded file"
            session['result_type'] = 'error'
            session['active_tab'] = 'chain-only'
            return redirect(url_for('index'))
        
        # Extract info for all certificates
        certs_info = [validator.extract_certificate_info(cert) for cert in certificates]
        
        # Verify chain order
        is_correct_order, correct_chain, order_message = validator.verify_certificate_chain_order(certificates)
        
        # Validation results
        validation_results = []
        
        # Check number of certificates
        validation_results.append({
            'check': 'Certificate Count',
            'status': True,
            'message': f"Found {len(certificates)} certificate(s) in the chain"
        })
        
        # Check chain order
        validation_results.append({
            'check': 'Chain Order',
            'status': is_correct_order,
            'message': order_message if is_correct_order else "Chain is NOT in correct order (should be: server → intermediate → root)"
        })
        
        # Check each certificate validity
        now = datetime.datetime.utcnow()
        for i, cert_info in enumerate(certs_info):
            cert_name = cert_info['subject'].get('commonName', f'Certificate {i+1}')
            if now > cert_info['not_after']:
                validation_results.append({
                    'check': f'Certificate Validity [{i+1}]',
                    'status': False,
                    'message': f"{cert_name} has expired ({cert_info['not_after']})"
                })
            elif now < cert_info['not_before']:
                validation_results.append({
                    'check': f'Certificate Validity [{i+1}]',
                    'status': False,
                    'message': f"{cert_name} is not yet valid (starts {cert_info['not_before']})"
                })
            else:
                days_until_expiry = (cert_info['not_after'] - now).days
                validation_results.append({
                    'check': f'Certificate Validity [{i+1}]',
                    'status': True,
                    'message': f"{cert_name} is valid ({days_until_expiry} days until expiry)"
                })
        
        # Check if chain is complete (has root)
        has_root = any(cert.subject == cert.issuer for cert in certificates)
        validation_results.append({
            'check': 'Chain Completeness',
            'status': has_root,
            'message': "Chain includes root certificate" if has_root else "Chain does not include root certificate (may need to be fetched)"
        })
        
        # Prepare result summary
        result_lines = ["Certificate Chain Analysis\n" + "="*40 + "\n"]
        result_lines.append(f"Certificates found: {len(certificates)}")
        result_lines.append(f"Current order: {'CORRECT' if is_correct_order else 'INCORRECT'}\n")
        
        # Show current chain
        result_lines.append("Current chain order:")
        for i, cert_info in enumerate(certs_info):
            is_ca = cert_info.get('is_ca', False)
            cert_type = "CA" if is_ca else "End-entity"
            result_lines.append(f"  {i+1}. {cert_info['subject'].get('commonName', 'Unknown')} ({cert_type})")
            result_lines.append(f"      Issuer: {cert_info['issuer'].get('commonName', 'Unknown')}")
        
        if not is_correct_order:
            result_lines.append("\nCorrect chain order should be:")
            correct_info = [validator.extract_certificate_info(cert) for cert in correct_chain]
            for i, cert_info in enumerate(correct_info):
                is_ca = cert_info.get('is_ca', False)
                cert_type = "CA" if is_ca else "End-entity"
                result_lines.append(f"  {i+1}. {cert_info['subject'].get('commonName', 'Unknown')} ({cert_type})")
        
        result_lines.append("\nValidation Results:")
        for result in validation_results:
            status = "✅" if result['status'] else "❌"
            result_lines.append(f"{status} {result['check']}: {result['message']}")
        
        # Determine overall result type
        if all(r['status'] for r in validation_results):
            result_type = 'success'
        elif is_correct_order:
            result_type = 'warning'
        else:
            result_type = 'error'
        
        # Save original chain
        session_id = session.get('_id', 'default')
        chain_pem = b''
        for cert in certificates:
            chain_pem += cert.public_bytes(serialization.Encoding.PEM)
        
        chain_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}chain_{session_id}.pem")
        with open(chain_path, 'wb') as f:
            f.write(chain_pem)
        
        # Prepare download links
        download_links = {
            'chain': '/download/chain',
            'report': '/download/report',
            'json': '/download/json'
        }
        
        # Save fixed chain if order was incorrect
        if not is_correct_order:
            fixed_chain_pem = b''
            # Filter out root if not wanted
            output_chain = correct_chain
            if not include_root:
                output_chain = [cert for cert in correct_chain if cert.subject != cert.issuer]
            
            for cert in output_chain:
                fixed_chain_pem += cert.public_bytes(serialization.Encoding.PEM)
            
            fixed_chain_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}fixed_chain_{session_id}.pem")
            with open(fixed_chain_path, 'wb') as f:
                f.write(fixed_chain_pem)
            
            download_links['fixed_chain'] = '/download/fixed_chain'
            result_lines.append(f"\n⚠️ Chain order needs fixing. Download the corrected chain below.")
        
        # Generate reports
        report_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.pdf")
        chain_info = [validator.extract_certificate_info(c) for c in certificates]
        validator.generate_pdf_report(certs_info[0] if certs_info else {}, chain_info, validation_results, report_path)
        
        json_path = os.path.join(TEMP_DIR, f"{TEMP_FILE_PREFIX}report_{session_id}.json")
        validator.generate_json_report(certs_info[0] if certs_info else {}, chain_info, validation_results, json_path)
        
        # Set session data
        session['result'] = '\n'.join(result_lines)
        session['result_type'] = result_type
        session['download_links'] = download_links
        session['active_tab'] = 'chain-only'
        
    except Exception as e:
        logger.error(f"Chain validation error: {str(e)}", exc_info=True)
        session['result'] = f"Chain validation error: {str(e)}"
        session['result_type'] = 'error'
        session['active_tab'] = 'chain-only'
    finally:
        validator.cleanup()
    
    return redirect(url_for('index'))

@app.route('/download/<file_type>')
def download_file(file_type):
    session_id = session.get('_id', 'default')
    file_map = {
        'chain': (f"{TEMP_FILE_PREFIX}chain_{session_id}.pem", "certificate_chain.pem"),
        'fixed_chain': (f"{TEMP_FILE_PREFIX}fixed_chain_{session_id}.pem", "certificate_chain_fixed.pem"),
        'report': (f"{TEMP_FILE_PREFIX}report_{session_id}.pdf", "certificate_report.pdf"),
        'json': (f"{TEMP_FILE_PREFIX}report_{session_id}.json", "certificate_report.json")
    }
    
    if file_type not in file_map:
        flash('Invalid download request.', 'error')
        return redirect(url_for('index'))
    
    temp_filename, download_name = file_map[file_type]
    file_path = os.path.join(TEMP_DIR, temp_filename)
    
    if not os.path.exists(file_path):
        flash('File not found. Please validate again.', 'error')
        return redirect(url_for('index'))
    
    return send_file(file_path, as_attachment=True, download_name=download_name)

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    return jsonify({'status': 'healthy'}), 200

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('index'))

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}", exc_info=True)
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
