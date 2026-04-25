from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import io
from datetime import datetime
import secrets
import requests
from PIL import Image as PILImage
import tempfile
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///image_encryption.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted'), exist_ok=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    images = db.relationship('Image', backref='user', lazy=True, cascade='all, delete-orphan')

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=True)
    encryption_key = db.Column(db.Text, nullable=True)
    algorithm = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Encryption Helper Functions
def generate_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_image(image_data, password, algorithm='AES'):
    if algorithm == 'AES':
        key, salt = generate_key_from_password(password)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(image_data)
        # Store salt with encrypted data for decryption
        return salt + encrypted_data, password  # Store password for decryption
    elif algorithm == 'XOR':
        # Simple XOR encryption
        key_bytes = password.encode()
        encrypted_data = bytearray()
        for i, byte in enumerate(image_data):
            encrypted_data.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(encrypted_data), password
    else:
        raise ValueError("Unsupported encryption algorithm")

def decrypt_image(encrypted_data, password, algorithm='AES'):
    if algorithm == 'AES':
        try:
            # Extract salt from encrypted data
            salt = encrypted_data[:16]
            actual_encrypted_data = encrypted_data[16:]
            key, _ = generate_key_from_password(password, salt)
            fernet = Fernet(key)
            return fernet.decrypt(actual_encrypted_data)
        except Exception as e:
            # Try alternative decryption methods for legacy data
            try:
                # Method 1: Try without salt extraction (for older data)
                key, _ = generate_key_from_password(password, b'salt_placeholder')
                fernet = Fernet(key)
                return fernet.decrypt(encrypted_data)
            except:
                # Method 2: Try with different salt handling
                try:
                    if len(encrypted_data) > 32:
                        # Try using first 16 bytes as salt but with different key derivation
                        salt = encrypted_data[:16]
                        actual_data = encrypted_data[16:]
                        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                        from cryptography.hazmat.primitives import hashes
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                        fernet = Fernet(key)
                        return fernet.decrypt(actual_data)
                except:
                    pass
                # If all methods fail, raise the original error
                raise ValueError(f"Decryption failed: Invalid password or corrupted data. Original error: {str(e)}")
    elif algorithm == 'XOR':
        key_bytes = password.encode()
        decrypted_data = bytearray()
        for i, byte in enumerate(encrypted_data):
            decrypted_data.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(decrypted_data)
    else:
        raise ValueError("Unsupported encryption algorithm")

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('signup.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('signup.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_images = Image.query.filter_by(user_id=session['user_id']).order_by(Image.created_at.desc()).all()
    return render_template('dashboard.html', images=user_images)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle both 'image' and 'images' field names
        files = []
        
        # Check for 'images' field (direct upload)
        if 'images' in request.files:
            files.extend(request.files.getlist('images'))
        
        # Check for 'image' field (legacy)
        if 'image' in request.files:
            files.extend(request.files.getlist('image'))
        
        # Filter valid files
        valid_files = [f for f in files if f.filename != '']
        
        if not valid_files:
            flash('No file selected', 'error')
            return render_template('upload.html')
        
        algorithm = request.form.get('algorithm', 'AES')
        encryption_password = request.form.get('encryption_password')
        
        if not encryption_password:
            flash('Encryption password is required', 'error')
            return render_template('upload.html')
        
        uploaded_count = 0
        failed_count = 0
        error_messages = []
        
        for file in valid_files:
            try:
                # Validate file extension
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'ico'}
                filename = secure_filename(file.filename)
                
                if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                    error_messages.append(f"Invalid file type: {filename}. Only images are allowed.")
                    failed_count += 1
                    continue
                
                # Read and validate image
                file.seek(0)  # Reset file pointer to beginning
                image_data = file.read()
                
                if not image_data:
                    error_messages.append(f"Empty file: {filename}")
                    failed_count += 1
                    continue
                
                try:
                    # Validate image using PIL
                    img = PILImage.open(io.BytesIO(image_data))
                    img.verify()  # Verify it's a valid image
                    
                    # Re-open for processing (verify() closes the image)
                    img = PILImage.open(io.BytesIO(image_data))
                    
                    # Convert to RGB if necessary (for consistency)
                    if img.mode in ('RGBA', 'LA', 'P'):
                        img = img.convert('RGB')
                    
                    # Save processed image to bytes
                    processed_data = io.BytesIO()
                    img.save(processed_data, format='JPEG', quality=95)
                    image_data = processed_data.getvalue()
                    
                except Exception as img_error:
                    error_messages.append(f"Invalid image file: {filename} - {str(img_error)}")
                    failed_count += 1
                    continue
                
                # Encrypt image
                encrypted_data, key = encrypt_image(image_data, encryption_password, algorithm)
                
                # Save encrypted file
                encrypted_filename = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', encrypted_filename)
                with open(encrypted_filepath, 'wb') as f:
                    f.write(encrypted_data)
                
                # Save to database
                image_record = Image(
                    filename=encrypted_filename,
                    original_filename=filename,
                    encrypted_filename=encrypted_filename,
                    encryption_key=key,
                    algorithm=algorithm,
                    file_size=len(image_data),
                    user_id=session['user_id']
                )
                db.session.add(image_record)
                uploaded_count += 1
                
            except Exception as e:
                error_messages.append(f"Error processing {filename}: {str(e)}")
                failed_count += 1
                continue
        
        # Commit all database changes
        try:
            db.session.commit()
            
            if uploaded_count > 0:
                if failed_count > 0:
                    flash(f'Successfully uploaded {uploaded_count} images. {failed_count} files failed.', 'warning')
                    if error_messages:
                        flash('Errors: ' + '; '.join(error_messages[:3]), 'error')
                else:
                    if uploaded_count == 1:
                        flash('Image uploaded and encrypted successfully!', 'success')
                    else:
                        flash(f'Successfully uploaded and encrypted {uploaded_count} images!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('No images were uploaded successfully.', 'error')
                if error_messages:
                    flash('Errors: ' + '; '.join(error_messages[:3]), 'error')
                return render_template('upload.html')
                
        except Exception as e:
            db.session.rollback()
            flash(f'Database error: {str(e)}', 'error')
            return render_template('upload.html')
    
    return render_template('upload.html')

@app.route('/decrypt/<int:image_id>', methods=['GET', 'POST'])
def decrypt(image_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    image = Image.query.get_or_404(image_id)
    
    # Check if user owns this image
    if image.user_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        decryption_password = request.form.get('decryption_password')
        
        if not decryption_password:
            flash('Decryption password is required', 'error')
            return render_template('decrypt.html', image=image)
        
        try:
            # Verify encrypted file exists
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', image.encrypted_filename)
            if not os.path.exists(encrypted_filepath):
                flash('Encrypted file not found. Please re-upload the image.', 'error')
                return render_template('decrypt.html', image=image)
            
            # Read encrypted file
            with open(encrypted_filepath, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                flash('Encrypted file is empty or corrupted.', 'error')
                return render_template('decrypt.html', image=image)
            
            # Decrypt image
            try:
                decrypted_data = decrypt_image(encrypted_data, decryption_password, image.algorithm)
            except Exception as decrypt_error:
                flash(f'Invalid password or corrupted data: {str(decrypt_error)}', 'error')
                return render_template('decrypt.html', image=image)
            
            if not decrypted_data:
                flash('Decryption failed - no data recovered.', 'error')
                return render_template('decrypt.html', image=image)
            
            # Ensure decrypted directory exists
            decrypted_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted')
            os.makedirs(decrypted_dir, exist_ok=True)
            
            # Save decrypted file temporarily
            decrypted_filename = f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.original_filename}"
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted', decrypted_filename)
            with open(decrypted_filepath, 'wb') as f:
                f.write(decrypted_data)
            
            # Verify decrypted file was created
            if not os.path.exists(decrypted_filepath):
                flash('Failed to save decrypted file.', 'error')
                return render_template('decrypt.html', image=image)
            
            flash('Image decrypted successfully!', 'success')
            return send_file(decrypted_filepath, as_attachment=True, download_name=image.original_filename)
            
        except Exception as e:
            flash(f'Error decrypting image: {str(e)}', 'error')
            return render_template('decrypt.html', image=image)
    
    return render_template('decrypt.html', image=image)

@app.route('/delete/<int:image_id>', methods=['POST'])
def delete_image(image_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    image = Image.query.get_or_404(image_id)
    
    # Check if user owns this image or is admin
    if image.user_id != session['user_id'] and not session.get('is_admin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete encrypted file
        if image.encrypted_filename:
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', image.encrypted_filename)
            if os.path.exists(encrypted_filepath):
                os.remove(encrypted_filepath)
        
        # Delete database record
        db.session.delete(image)
        db.session.commit()
        
        flash('Image deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting image: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    images = Image.query.all()
    return render_template('admin.html', users=users, images=images)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin'))
    
    try:
        # Delete user's images
        for image in user.images:
            if image.encrypted_filename:
                encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', image.encrypted_filename)
                if os.path.exists(encrypted_filepath):
                    os.remove(encrypted_filepath)
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        flash('User deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('admin'))

# Direct Upload Routes
@app.route('/direct_upload', methods=['GET', 'POST'])
def direct_upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle direct file upload
        if 'images' not in request.files:
            flash('No files selected', 'error')
            return render_template('direct_upload.html')
        
        files = request.files.getlist('images')
        valid_files = [f for f in files if f.filename != '']
        
        if not valid_files:
            flash('No files selected', 'error')
            return render_template('direct_upload.html')
        
        algorithm = request.form.get('algorithm', 'AES')
        encryption_password = request.form.get('encryption_password')
        
        if not encryption_password:
            flash('Encryption password is required', 'error')
            return render_template('direct_upload.html')
        
        uploaded_count = 0
        failed_count = 0
        error_messages = []
        
        for file in valid_files:
            try:
                # Validate file extension
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'ico'}
                filename = secure_filename(file.filename)
                
                if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                    error_messages.append(f"Invalid file type: {filename}. Only images are allowed.")
                    failed_count += 1
                    continue
                
                # Read and validate image
                file.seek(0)  # Reset file pointer to beginning
                image_data = file.read()
                
                if not image_data:
                    error_messages.append(f"Empty file: {filename}")
                    failed_count += 1
                    continue
                
                try:
                    # Validate image using PIL
                    img = PILImage.open(io.BytesIO(image_data))
                    img.verify()  # Verify it's a valid image
                    
                    # Re-open for processing (verify() closes the image)
                    img = PILImage.open(io.BytesIO(image_data))
                    
                    # Convert to RGB if necessary (for consistency)
                    if img.mode in ('RGBA', 'LA', 'P'):
                        img = img.convert('RGB')
                    
                    # Save processed image to bytes
                    processed_data = io.BytesIO()
                    img.save(processed_data, format='JPEG', quality=95)
                    image_data = processed_data.getvalue()
                    
                except Exception as img_error:
                    error_messages.append(f"Invalid image file: {filename} - {str(img_error)}")
                    failed_count += 1
                    continue
                
                # Encrypt image
                encrypted_data, key = encrypt_image(image_data, encryption_password, algorithm)
                
                # Save encrypted file
                encrypted_filename = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', encrypted_filename)
                with open(encrypted_filepath, 'wb') as f:
                    f.write(encrypted_data)
                
                # Save to database
                image_record = Image(
                    filename=encrypted_filename,
                    original_filename=filename,
                    encrypted_filename=encrypted_filename,
                    encryption_key=key,
                    algorithm=algorithm,
                    file_size=len(image_data),
                    user_id=session['user_id']
                )
                db.session.add(image_record)
                uploaded_count += 1
                
            except Exception as e:
                error_messages.append(f"Error processing {filename}: {str(e)}")
                failed_count += 1
                continue
        
        # Commit all database changes
        try:
            db.session.commit()
            
            if uploaded_count > 0:
                if failed_count > 0:
                    flash(f'Successfully uploaded {uploaded_count} images. {failed_count} files failed.', 'warning')
                    if error_messages:
                        flash('Errors: ' + '; '.join(error_messages[:3]), 'error')
                else:
                    if uploaded_count == 1:
                        flash('Image uploaded and encrypted successfully!', 'success')
                    else:
                        flash(f'Successfully uploaded and encrypted {uploaded_count} images!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('No images were uploaded successfully.', 'error')
                if error_messages:
                    flash('Errors: ' + '; '.join(error_messages[:3]), 'error')
                return render_template('direct_upload.html')
                
        except Exception as e:
            db.session.rollback()
            flash(f'Database error: {str(e)}', 'error')
            return render_template('direct_upload.html')
    
    return render_template('direct_upload.html')

# URL Upload Routes
@app.route('/upload_from_url', methods=['GET', 'POST'])
def upload_from_url():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        image_url = request.form.get('image_url')
        algorithm = request.form.get('algorithm', 'AES')
        encryption_password = request.form.get('encryption_password')
        
        if not image_url:
            flash('Image URL is required', 'error')
            return render_template('upload_from_url.html')
        
        if not encryption_password:
            flash('Encryption password is required', 'error')
            return render_template('upload_from_url.html')
        
        try:
            # Download image from URL
            response = requests.get(image_url, timeout=30)
            response.raise_for_status()
            
            # Check if content is an image
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('image/'):
                flash('URL does not point to an image file', 'error')
                return render_template('upload_from_url.html')
            
            # Get filename from URL or create one
            filename = image_url.split('/')[-1]
            if not filename or '.' not in filename:
                filename = 'downloaded_image.jpg'
            
            filename = secure_filename(filename)
            image_data = response.content
            
            # Validate image using PIL
            try:
                img = PILImage.open(io.BytesIO(image_data))
                img.verify()  # Verify it's a valid image
                
                # Re-open for processing (verify() closes the image)
                img = PILImage.open(io.BytesIO(image_data))
                
                # Convert to RGB if necessary (for consistency)
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                # Save processed image to bytes
                processed_data = io.BytesIO()
                img.save(processed_data, format='JPEG', quality=95)
                image_data = processed_data.getvalue()
                
            except Exception as img_error:
                flash('Invalid image file from URL', 'error')
                return render_template('upload_from_url.html')
            
            # Encrypt and save
            encrypted_data, key = encrypt_image(image_data, encryption_password, algorithm)
            
            encrypted_filename = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted', encrypted_filename)
            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted_data)
            
            # Save to database
            image_record = Image(
                filename=encrypted_filename,
                original_filename=filename,
                encrypted_filename=encrypted_filename,
                encryption_key=key,
                algorithm=algorithm,
                file_size=len(image_data),
                user_id=session['user_id']
            )
            db.session.add(image_record)
            db.session.commit()
            
            flash('Image downloaded and encrypted successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except requests.RequestException as e:
            flash(f'Error downloading image: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error processing image: {str(e)}', 'error')
    
    return render_template('upload_from_url.html')


@app.route('/scan_directory', methods=['POST'])
def scan_directory():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.json
        directory_path = data.get('directory_path', '')
        
        if not directory_path or not os.path.exists(directory_path):
            return jsonify({'error': 'Invalid directory path'}), 400
        
        # Scan for image files
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico'}
        image_files = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if Path(file).suffix.lower() in image_extensions:
                    full_path = os.path.join(root, file)
                    try:
                        # Verify it's actually an image
                        with Image.open(full_path) as img:
                            img.verify()
                        
                        # Get file info
                        file_size = os.path.getsize(full_path)
                        image_files.append({
                            'path': full_path,
                            'name': file,
                            'size': file_size,
                            'size_formatted': format_file_size(file_size)
                        })
                    except Exception:
                        continue  # Skip invalid images
        
        return jsonify({'success': True, 'files': image_files})
        
    except Exception as e:
        return jsonify({'error': f'Error scanning directory: {str(e)}'}), 500

def format_file_size(bytes_size):
    if bytes_size == 0:
        return "0 Bytes"
    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB"]
    i = int(math.floor(math.log(bytes_size) / math.log(k)))
    return "%.2f %s" % (bytes_size / math.pow(k, i), sizes[i])

# Add missing import
import math

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_password = generate_password_hash('admin123')
            admin = User(username='admin', email='admin@example.com', password_hash=admin_password, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: username=admin, password=admin123")
    
    app.run(debug=True)
