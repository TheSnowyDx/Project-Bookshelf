from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import requests
import os
from werkzeug.utils import secure_filename

user_routes = Blueprint('user_routes', __name__)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['Bookshelf']
users_collection = db['users']

# Route to change username
@user_routes.route('/username', methods=['GET', 'POST'])
def change_username():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Update username logic
        new_username = request.form.get('new_username')
        # Update username in the database
        users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'username': new_username}})
        return redirect(url_for('settings'))
    else:
        return render_template('change_username.html')

# Route to change email
@user_routes.route('/email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Update email logic
        new_email = request.form.get('new_email')
        # Update email in the database
        users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'email': new_email}})
        return redirect(url_for('settings'))
    else:
        return render_template('change_email.html')

# Route to change password
@user_routes.route('/password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Update password logic
        new_password = request.form.get('new_password')
        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        # Update password in the database
        users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'password': hashed_password}})
        return redirect(url_for('settings'))
    else:
        return render_template('reset_password.html')

UPLOAD_FOLDER = 'static/profiles/'  # Specify the folder where you want to store uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Specify the allowed file extensions

# Route to change privacy settings
@user_routes.route('/privacy')
def privacy_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Render privacy settings page
    return render_template('privacy_settings.html')

# Route to edit bio
@user_routes.route('/bio', methods=['GET', 'POST'])
def edit_bio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Update bio logic
        new_bio = request.form.get('new_bio')
        # Update bio in the database
        users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': {'bio': new_bio}})
        return redirect(url_for('settings'))
    else:
        return render_template('edit_bio.html')

# Route to update personal information
@user_routes.route('/personal', methods=['GET', 'POST'])
def update_personal_info():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Update personal information logic
        new_info = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'address': request.form.get('address'),
            # Add more fields as needed
        }
        # Update personal information in the database
        users_collection.update_one({'_id': ObjectId(session['user_id'])}, {'$set': new_info})
        return redirect(url_for('settings'))
    else:
        return render_template('update_personal_info.html')
