# 🔐 Secure Image Encryption and Decryption System

A comprehensive web-based application for securely encrypting and decrypting images with user authentication and administrative features.

## 🌟 Features

### 🔑 User Authentication
- **Secure Registration**: Sign up with username, email, and password
- **Login System**: Secure authentication with session management
- **Password Security**: Hashed passwords using Werkzeug
- **Admin Access**: Built-in admin panel for system management

### 🔒 Image Encryption
- **Multiple Algorithms**: 
  - AES (Advanced Encryption Standard) with PBKDF2 key derivation
  - XOR encryption for faster processing
- **Secure Storage**: Encrypted files stored safely on server
- **Password Protection**: Each image encrypted with unique password
- **File Validation**: Support for PNG, JPG, JPEG, GIF, BMP formats

### 🔓 Image Decryption
- **Secure Decryption**: Enter password to recover original images
- **Download Support**: Direct download of decrypted images
- **Attempt Limiting**: Security measures against brute force attacks
- **Persistent Storage**: Encrypted versions remain for future use

### 📊 Dashboard & Management
- **User Dashboard**: View and manage encrypted images
- **Admin Panel**: User management and system monitoring
- **Statistics**: Track usage and storage metrics
- **Modern UI**: Responsive design with smooth animations

## 🛠️ Tech Stack

### Backend
- **Flask**: Web framework
- **SQLAlchemy**: Database ORM
- **Werkzeug**: Security utilities
- **Cryptography**: Encryption/decryption operations

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Modern styling with animations
- **JavaScript**: Interactive features and validation
- **Responsive Design**: Mobile-friendly interface

### Database
- **SQLite**: Lightweight database storage
- **ORM Models**: User and Image entities

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step 1: Clone/Download the Project
```bash
# If you have the project files, navigate to the project directory
cd sahithi
```

### Step 2: Create Virtual Environment
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On Unix/MacOS
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```

The application will start on `http://localhost:5000`

## 📁 Project Structure

```
sahithi/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── uploads/              # File storage directory
│   ├── encrypted/       # Encrypted images
│   └── decrypted/        # Temporary decrypted files
├── templates/            # HTML templates
│   ├── base.html        # Base template
│   ├── login.html       # Login page
│   ├── signup.html      # Registration page
│   ├── dashboard.html    # User dashboard
│   ├── upload.html       # Image upload page
│   ├── decrypt.html      # Image decryption page
│   └── admin.html        # Admin panel
└── static/
    └── css/
        └── style.css     # Application styles
```

## 🔐 Default Admin Account

The system automatically creates an admin user on first run:

- **Username**: `admin`
- **Password**: `admin123`

⚠️ **Important**: Change the default admin password in production!

## 📖 Usage Guide

### 1. User Registration
1. Visit `/signup`
2. Enter username, email, and password
3. Password must be at least 8 characters
4. Click "Create Account"

### 2. Login
1. Visit `/login`
2. Enter username and password
3. Click "Sign In"

### 3. Upload & Encrypt Image
1. Go to `/upload` after login
2. Drag & drop or select an image file
3. Choose encryption algorithm (AES recommended)
4. Create a strong encryption password
5. Click "Upload & Encrypt Image"

### 4. Decrypt Image
1. Go to `/dashboard`
2. Click "Decrypt" on any encrypted image
3. Enter the encryption password used during upload
4. Click "Decrypt & Download"

### 5. Admin Panel (Admin Only)
1. Login as admin
2. Visit `/admin`
3. View user statistics and manage accounts
4. Delete users and their encrypted images

## 🔒 Security Features

### Encryption Algorithms
- **AES**: Military-grade encryption with PBKDF2 key derivation
- **XOR**: Fast encryption for less sensitive data

### Security Measures
- Password hashing with Werkzeug
- Session management
- File type validation
- Upload size limits (16MB max)
- Brute force protection
- Secure file storage

### Best Practices
- Store encryption passwords securely
- Use strong, unique passwords
- Regular backup of encrypted files
- Change default admin password
- Monitor user activity via admin panel

## 🛡️ Important Security Notes

⚠️ **Critical**: Encryption passwords are NOT stored in the database. If you lose an encryption password, the image cannot be recovered. This is intentional for security purposes.

🔐 **Recommendation**: Use a password manager to store encryption passwords securely.

## 🐛 Troubleshooting

### Common Issues

1. **Database Error**: 
   - Ensure SQLite is available
   - Delete `image_encryption.db` to reset

2. **Import Errors**:
   - Activate virtual environment
   - Install all dependencies

3. **File Upload Issues**:
   - Check file size (max 16MB)
   - Verify file format (PNG, JPG, JPEG, GIF, BMP)

4. **Decryption Failures**:
   - Ensure correct encryption password
   - Verify algorithm selection matches original

### Debug Mode
The application runs in debug mode by default. For production, set:
```python
app.run(debug=False)
```

## 🔄 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirect to login |
| GET/POST | `/signup` | User registration |
| GET/POST | `/login` | User authentication |
| GET | `/logout` | User logout |
| GET | `/dashboard` | User dashboard |
| GET/POST | `/upload` | Upload & encrypt image |
| GET/POST | `/decrypt/<id>` | Decrypt image |
| POST | `/delete/<id>` | Delete image |
| GET | `/admin` | Admin panel |
| POST | `/admin/delete_user/<id>` | Delete user |

## 🎯 Future Enhancements

- [ ] Two-factor authentication
- [ ] Email verification
- [ ] Password reset functionality
- [ ] Image preview thumbnails
- [ ] Bulk operations
- [ ] Export/Import functionality
- [ ] Advanced encryption algorithms
- [ ] Cloud storage integration
- [ ] API rate limiting
- [ ] Audit logging

## 📝 License

This project is for educational purposes. Use responsibly and in compliance with applicable laws and regulations.

## 🤝 Contributing

1. Fork the project
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the error logs
3. Verify configuration settings
4. Test with different browsers

---

**⚠️ Disclaimer**: This software is provided as-is for educational purposes. The developers are not responsible for data loss or security breaches. Always test thoroughly before production use.
