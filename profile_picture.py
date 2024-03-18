# profile_picture.py

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os

profile_picture_routes = Blueprint('profile_picture_routes', __name__)

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Configure upload folder
UPLOAD_FOLDER = os.path.join('static', 'images')

@profile_picture_routes.route('/picture', methods=['GET', 'POST'])
def upload_picture():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'picture' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['picture']
        
        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # Check if the file is allowed (e.g., only images)
        if file and allowed_file(file.filename):
            # Save the uploaded file to the upload folder
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            
            # Here, you would typically update the user's profile picture field in the database
            # Example: user.profile_picture = filename
            # After updating the database, redirect to the profile page
            return redirect(url_for('user_routes.upload_picture'))

    return render_template('upload_picture.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
