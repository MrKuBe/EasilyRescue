# EasilyRescue 🚑

**Business Continuity Tool for Easily DPI**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)

## 📋 Description

EasilyRescue is a business continuity application (BCP) for services using the **Easily** electronic health record (EHR) software from the Civil Hospitals of Lyon (HCL).

In case of EHR unavailability, the application automates:
- ✅ Retrieval of archives from an SFTP server
- ✅ Decompression and indexing of files
- ✅ Generation of an interactive HTML report to view patient documents

## 🚀 Features

- **Secure SFTP connection** : Support for password or SSH private key
- **Parallel download** : Optimized archive retrieval
- **Integrity verification** : SHA256 validation of each file
- **Clean download mode** : Temporary cache to guarantee data consistency
- **Parallel decompression** : Fast processing of ZIP archives
- **Dynamic HTML report** : Web interface with search, sort and filter
- **Detailed logging** : Complete logs for audit and troubleshooting

## ⚙️ Installation

### Prerequisites
- Python 3.8+
- Git

### Dependencies

EasilyRescue uses only minimal standard and external Python libraries:

#### Standard libraries (included with Python)
- `json` - JSON and JSONC data manipulation
- `re` - Regular expressions for comment cleaning
- `logging` - Event logging
- `pathlib` - Cross-platform path management
- `typing` - Type annotations
- `zipfile` - ZIP archive decompression
- `datetime` - Date and timestamp management
- `os` - Operating system interaction
- `time` - Execution time measurement
- `hashlib` - SHA256 checksum calculation
- `concurrent.futures` - Parallel task execution
- `tempfile` - Secure temporary file creation
- `shutil` - File/folder operations
- `sys` - Python interpreter interaction
- `webbrowser` - Automatic HTML report opening
- `html` - Special character escaping

#### External libraries to install
| Package | Version | Purpose |
|---------|---------|---------|
| **paramiko** | ≥2.7.0 | SFTP implementation for secure connection and transfer |
| **tqdm** | ≥4.50.0 | Intelligent and aesthetic progress bars |

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-username/EasilyRescue.git
cd EasilyRescue

# 2. Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate

# 3. Install external dependencies
pip install paramiko tqdm

# Optional: verify installation
pip list

# 4. Configure the application
cp config.example.jsonc config.jsonc
# Edit config.jsonc with your SFTP parameters
```

### Installation Verification

```bash
# Verify Python is correctly configured
python --version  # Should display Python 3.8+

# Test dependency imports
python -c "import paramiko; import tqdm; print('✅ Dependencies OK')"
```

## 🔧 Configuration

### File `config.jsonc`

1. **Copy from template** :
   ```bash
   cp config.example.jsonc config.jsonc
   ```

2. **Fill SFTP parameters** :
   ```jsonc
   {
       "sftp": {
           "hostname": "your_server.com",
           "username": "your_username",
           "password": "your_password",
           // OR use SSH private key
           "private_key_path": "~/.ssh/id_rsa"
       }
   }
   ```

### 🔐 Security

- ⚠️ **Never commit** `config.jsonc` to Git
- ✅ Use `config.example.jsonc` as template
- ✅ The file `config.jsonc` is in `.gitignore`

## 🚀 Usage

```bash
# Launch the application
python EasilyRescue.py

# The application will:
# 1. Read the configuration
# 2. Connect to the SFTP server
# 3. Download archives
# 4. Decompress files
# 5. Generate the HTML report (index.html)
# 6. Automatically open in the browser
```

## 📊 Project Structure

```
EasilyRescue/
├── EasilyRescue.py          # Main code
├── config.example.jsonc     # Configuration template (to copy)
├── config.jsonc             # Personal configuration (do not commit)
├── index.html               # Generated report (do not commit)
├── logs/                    # Execution logs (do not commit)
├── data/                    # Downloaded data (do not commit)
├── .gitignore               # Security rules
└── README.md                # This documentation
```

## 📋 Files Sent to GitHub

| File | Status | Description |
|------|--------|-------------|
| `EasilyRescue.py` | ✅ Sent | Source code |
| `config.example.jsonc` | ✅ Sent | Configuration template |
| `.gitignore` | ✅ Sent | Security rules |
| `README.md` | ✅ Sent | Documentation |
| `config.jsonc` | ❌ Excluded | Secrets (in .gitignore) |
| `logs/` | ❌ Excluded | System logs |
| `data/` | ❌ Excluded | Large data files |
| `index.html` | ❌ Excluded | Generated report |

## 🔍 Troubleshooting

### Data is not downloading
- Verify SFTP connection in `config.jsonc`
- Verify that the server is accessible
- Check the logs in `logs/`

### Decompression error
- Verify the integrity of ZIP files
- Make sure you have enough disk space

## 📝 Logs

Execution logs are available in the `logs/` folder:
```
logs/
├── main_2026_02_09.log
├── main_2026_02_10.log
└── main_2026_02_11.log
```

## 📄 License

This project is under the MIT License. See the [LICENSE](LICENSE) file for details.

## 👤 Author

- **Bertrand Kuzbinski** - Designer/Developer

## 🤝 Contributing

Contributions are welcome! Feel free to:
1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## 📞 Support

For any questions or issues, please:
- Open an issue on GitHub
- Check the logs in the `logs/` folder

---

**Last updated** : 11 February 2026
