from flask import Flask, redirect, url_for, session, render_template, jsonify, flash, request
from authlib.integrations.flask_client import OAuth
from user_routes import *
from pymongo import MongoClient
from bson import ObjectId
from bson.binary import Binary
import requests
from profile_picture import profile_picture_routes
import random
import bcrypt
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import hashlib

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Register the user routes blueprint
app.register_blueprint(user_routes)
app.register_blueprint(profile_picture_routes)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['Bookshelf']
books_collection = db['books']
users_collection = db['users']

# Define the Google Books API URL and API key
GOOGLE_BOOKS_API_URL = 'https://www.googleapis.com/books/v1/volumes'
API_KEY = 'AIzaSyBcYaFL98-L1A8x4yxsaUxUEhqEsQQBZ_0'

appConf = {
    "OAUTH2_CLIENT_ID": "702561852963-r79igqhq5qsen3ofg111u8fs3po6ti6d.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": app.secret_key,
    "FLASK_PORT": 3000
}

oauth = OAuth(app)

oauth.register("projectBookshelf",
               client_id=appConf.get("OAUTH2_CLIENT_ID"),
               client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
               server_metadata_url=appConf.get("OAUTH2_META_URL"),
               client_kwargs={
                   "scope": "openid profile email"
               },
               redirect_to="google_login"
               )

@app.route("/google-login")
def googleLogin():
    return oauth.projectBookshelf.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))


@app.route("/signin-google")
def googleCallback():
    token = oauth.projectBookshelf.authorize_access_token()
    session["user"] = token
    return redirect(url_for("index"))
# @app.route("/google-login")
# def google_login():
#     return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))
#     # if not google.authorized:
#     #     return redirect(url_for("google.login"))
#     # resp = google.get("/oauth2/v2/userinfo")
#     # assert resp.ok, resp.text
#     # email = resp.json().get("email")
#     # if email:
#     #     return f"You are {email} on Google"
#     # else:
#     #     return "Email not available"

# @app.route("/logout")
# def logout():
#     google.logout()
#     return redirect(url_for("index"))

# @app.route('/auth/twitter')
# def twitter_login():
#     twitter = OAuth1Session(
#         'your_twitter_consumer_key',
#         client_secret='your_twitter_consumer_secret',
#         callback_uri=url_for('twitter_authorized', _external=True)
#     )
#     fetch_response = twitter.fetch_request_token('https://api.twitter.com/oauth/request_token')
#     session['oauth_token'] = fetch_response.get('oauth_token')
#     session['oauth_token_secret'] = fetch_response.get('oauth_token_secret')
#     auth_url = twitter.authorization_url('https://api.twitter.com/oauth/authorize')
#     return redirect(auth_url)

# @app.route('/auth/twitter/callback')
# def twitter_authorized():
#     if 'oauth_token' not in session or 'oauth_verifier' not in request.args:
#         return 'Access denied: OAuth token missing'
    
#     oauth_token = session.pop('oauth_token')
#     oauth_token_secret = session.pop('oauth_token_secret')
#     oauth_verifier = request.args['oauth_verifier']
    
#     twitter = OAuth1Session(
#         'your_twitter_consumer_key',
#         client_secret='your_twitter_consumer_secret',
#         resource_owner_key=oauth_token,
#         resource_owner_secret=oauth_token_secret,
#         verifier=oauth_verifier
#     )
#     access_response = twitter.fetch_access_token('https://api.twitter.com/oauth/access_token')
#     # Use the access token to fetch user information from Twitter
#     # Create or authenticate the user in your system
#     # Log the user in and redirect them to the appropriate page

# facebook = oauth.remote_app(
#     'facebook',
#     consumer_key='your_facebook_app_id',
#     consumer_secret='your_facebook_app_secret',
#     request_token_params={'scope': 'email'},
#     base_url='https://graph.facebook.com/',
#     request_token_url=None,
#     access_token_method='POST',
#     access_token_url='/oauth/access_token',
#     authorize_url='https://www.facebook.com/dialog/oauth'
# )

# @app.route('/auth/facebook')
# def facebook_login():
#     return facebook.authorize(callback=url_for('facebook_authorized', _external=True))

# @app.route('/auth/facebook/callback')
# def facebook_authorized():
#     resp = facebook.authorized_response()
#     if resp is None or 'access_token' not in resp:
#         return 'Access denied: reason={}, error={}'.format(
#             request.args['error_reason'],
#             request.args['error_description']
#         )

#     session['facebook_token'] = (resp['access_token'], '')
#     # Fetch user information from Facebook API
#     # Create or authenticate the user in your system
#     # Log the user in and redirect them to the appropriate page

#     # Redirect to the dashboard page after successful authentication
#     return redirect(url_for('dashboard'))

# @facebook.tokengetter
# def get_facebook_oauth_token():
#     return session.get('facebook_token')

@app.route('/display.html')
def display():
    title = request.args.get('title', '')
    authors = request.args.get('authors', '')
    description = request.args.get('description', '')
    
    book_details = {}
    try:
        response = requests.get(GOOGLE_BOOKS_API_URL, params={'q': f'intitle:{title}+inauthor:{authors}', 'key': API_KEY})
        response.raise_for_status()
        book_data = response.json()
        if 'items' in book_data:
            book_info = book_data['items'][0]['volumeInfo']
            book_details['title'] = book_info.get('title', '')
            book_details['authors'] = ', '.join(book_info.get('authors', []))
            book_details['description'] = book_info.get('description', '')
            book_details['preview_link'] = book_info.get('previewLink', '')
    except requests.RequestException as e:
        return f"An error occurred: {str(e)}"
    
    user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})

    # Pass the book details and user information to the display.html template
    return render_template('display.html', book_details=book_details, user=user)


# Function to generate a unique book ID based on book details
def generate_book_id(book_details):
    unique_string = f"{book_details['title']}_{book_details['author']}"
    book_id = hashlib.sha256(unique_string.encode()).hexdigest()
    return book_id

@app.route('/add-to-bookshelf', methods=['POST'])
def add_to_bookshelf():
    if 'user_id' not in session:
        flash('Please log in to add books to your bookshelf', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    # Extract book details from the request form
    book_details = {
        'title': request.form.get('title'),
        'author': request.form.get('author'),
        'description': request.form.get('description')
    }

    # Fetch and convert cover image to binary data
    cover_url = request.form.get('cover')
    if cover_url:
        cover_image = requests.get(cover_url).content
        cover_binary = Binary(cover_image)
        book_details['cover'] = cover_binary

    # Generate a unique book ID for the book
    book_id = generate_book_id(book_details)

    # Update user's document in the database to add the book to their bookshelf
    users_collection.update_one({'_id': ObjectId(user_id)}, {'$addToSet': {'bookshelf': {'book_id': book_id, 'details': book_details}}})

    return redirect(url_for('books'))  # Redirect to books route

@app.route('/books')
def books():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Flash the success message here, after redirecting to the books route
    flash('Book added to your bookshelf', 'success')

    user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        username = user.get('username', '')  # Get the username
        profile_picture = user.get('profile_picture', '') 
    
    books_info = None
    query = request.args.get('q', '')
    if query:
        try:
            response = requests.get('https://www.googleapis.com/books/v1/volumes', params={'q': query, 'maxResults': 100, 'key': API_KEY})
            response.raise_for_status()
            books_info = response.json().get('items', [])  # Extract 'items' from the response
        except requests.RequestException as e:
            return f"An error occurred: {str(e)}"
    
    return render_template('explore.html', books_info=books_info, user=user, username=username, profile_picture=profile_picture)

@app.route('/recommendations')
def recommendations():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        username = user.get('username', '')  # Get the username
        profile_picture = user.get('profile_picture', '') 

    # Fetch multiple pages of book recommendations from Google Books API
    books_info = []
    for page in range(1, 5):  # Fetch 4 pages of recommendations
        try:
            response = requests.get(GOOGLE_BOOKS_API_URL, params={'q': 'subject:fiction', 'startIndex': (page - 1) * 40, 'maxResults': 40, 'key': API_KEY})
            response.raise_for_status()
            books_info += response.json().get('items', [])  # Extract 'items' from the response
        except requests.RequestException as e:
            return f"An error occurred: {str(e)}"

    return render_template('recommendations.html', books_info=books_info, user=user, username=username, profile_picture=profile_picture)


# Rectified /bookshelf route
@app.route('/bookshelf')
def bookshelf():
    if 'user_id' not in session:
        flash('Please log in to view your bookshelf', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    bookshelf = user.get('bookshelf', [])

    # Function to get the rating for a book
    def get_rating_for_book(book_id):
        try:
            book = users_collection.find_one({'_id': ObjectId(user_id), 'bookshelf.book_id': book_id})
            if book:
                for book_info in book['bookshelf']:
                    if book_info['book_id'] == book_id:
                        return book_info.get('rating', 0)
            return 0
        except Exception as e:
            print("Error:", e)
            return 0

    # Add 'rating' attribute to each book in the bookshelf
    for book in bookshelf:
        book['rating'] = get_rating_for_book(book['book_id'])

    return render_template('bookshelf.html', bookshelf=bookshelf)

# Route for the index page
@app.route('/', methods=['GET'])
def index():
    # Check if the user is logged in
    username = None
    profile_picture = None
    if 'user_id' in session:
        # If the user is logged in, fetch user data
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        username = user.get('username', '')  # Get the username
        profile_picture = user.get('profile_picture', '') 
    else:
        # If the user is not logged in, set user data to None
        user = None

    # Initialize an empty list for featured books
    featured_books = []

    try:
        # Fetch 3 random books from Google Books API
        for _ in range(3):
            random_query = ' '.join([random.choice(['romance', 'fantasy', 'science fiction', 'mystery', 'horror', 'fiction'])])
            response = requests.get(GOOGLE_BOOKS_API_URL, params={'q': random_query, 'key': API_KEY})
            response.raise_for_status()
            books_info = response.json().get('items', [])
            
            if books_info:
                # Select a random book from the response
                book_info = random.choice(books_info)['volumeInfo']
                # Append book details to the featured_books list
                featured_books.append({
                    'title': book_info.get('title', ''),
                    'author': ', '.join(book_info.get('authors', [])),
                    'image': book_info.get('imageLinks', {}).get('thumbnail', ''),
                    'preview_link': book_info.get('previewLink', '')
                })

        # If there are fewer than 3 books found, supplement with hardcoded books
        while len(featured_books) < 3:
            featured_books.append({
                'title': f'Book Title {len(featured_books) + 1}',
                'author': f'Author Name {len(featured_books) + 1}',
                'image': f'/static/images/book{len(featured_books) + 1}.jpg',
                'preview_link': '#'
            })

    except requests.RequestException as e:
        print(f"An error occurred: {str(e)}")

    # Render the index.html template with the featured books and user data
    return render_template('index.html', featured_books=featured_books, user=user, username=username, profile_picture=profile_picture)

@app.route('/remove-book', methods=['GET', 'POST'])
def remove_book():
    if request.method == 'GET':
        # Retrieve the book_id from the query parameters
        book_id = request.args.get('book_id')
        
        # Remove the book with the specified book_id from the user's collection
        user_id = session.get('user_id')
        if user_id:
            result = users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$pull': {'bookshelf': {'book_id': book_id}}}
            )
            if result.modified_count > 0:
                flash('Book removed successfully', 'success')
            else:
                flash('Book not found or already removed', 'warning')
        else:
            flash('Please log in to remove books', 'warning')
    return redirect(url_for('bookshelf'))

@app.route('/rate-book', methods=['POST'])
def rate_book():
    if request.method == 'POST':
        # Retrieve book_id and rating from the request data
        book_id = request.form.get('book_id')
        rating = int(request.form.get('rating'))

        # Validate book_id and rating
        if not book_id or not rating:
            return jsonify({'success': False, 'error': 'Invalid input data'}), 400

        # Retrieve user_id from the session
        user_id = session.get('user_id')
        
        if user_id:
            # Update the rating for the specified book in the user's collection
            result = users_collection.update_one(
                {'_id': ObjectId(user_id), 'bookshelf.book_id': book_id},
                {'$set': {'bookshelf.$.rating': rating}}
            )

            if result.matched_count > 0:
                return jsonify({'success': True}), 200
            else:
                return jsonify({'success': False, 'error': 'Book not found or already removed'}), 404
        else:
            return jsonify({'success': False, 'error': 'Please log in to rate books'}), 401

# Route for the themes page
@app.route('/themes', methods=['GET'])
def themes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('themes.html')

# Route for setting up the database
@app.route('/setup-database', methods=['GET'])
def setup_database():
    try:
        books_collection.drop()
        users_collection.drop()

        books_collection.insert_one({
            'title': 'Sample Book',
            'author': 'Sample Author',
            'genre': 'Sample Genre'
        })

        hashed_password = bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'username': 'sample_user',
            'email': 'sample@example.com',
            'password': hashed_password
        })

        return "Database setup complete!"
    except Exception as e:
        return f"An error occurred: {str(e)}"

# Route for logging in
# Route for logging in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({'username': username.lower()})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = str(user['_id'])
            return redirect(url_for('dashboard'))
        else:
            error_message = "Invalid username or password. Please try again."
            return render_template('login.html', error_message=error_message)
    else:
        return render_template('login.html')

@app.route('/logout')
def signout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    else:
        session.clear()
        return redirect('/')

# Route for the dashboard page
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'user_id' in session:
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        username = user.get('username', '')  # Get the username
        profile_picture = user.get('profile_picture', '') 
    
        if user:
            return render_template('dashboard.html', user_id=user_id, username=username, profile_picture=profile_picture)
    
    return "You need to log in first."

# Route for registering
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']

        username_lower = username.lower()
        email_lower = email.lower()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            new_user = {
                'username': username_lower,
                'email': email_lower,
                'password': hashed_password,
                'phone_number': phone
            }
            users_collection.insert_one(new_user)

            return redirect(url_for('login'))
        except Exception as e:
            print("Error:", e)
            return "An error occurred while registering. Please try again later."
    else:
        return render_template('register.html')

# Route for settings
@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    username = user.get('username', '')  # Get the username
    profile_picture = user.get('profile_picture', '')     
    if user:
        return render_template('settings.html', user=user, username=username, profile_picture=profile_picture)
    
    return "You need to log in first."

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    message = None  # Initialize message variable
    
    if request.method == 'POST':
        user_email = request.form.get('email')
        
        # Check if the email exists in your database
        user = users_collection.find_one({'email': user_email})

        if user:
            # Generate a unique token and save it in the database
            token = generate_unique_token()
            # Send an email to the user with a link to the reset password page including the token
            send_reset_password_email(user_email, token)
            return redirect(url_for('login'))  # Redirect to login page after sending email
        else:
            message = 'Email address not found.'  # Set message if email not found

    # Render the forgot_password.html template with the message
    return render_template('forgot_password.html', message=message)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.args.get('token')
        password = request.form['password']

def generate_unique_token():
    # Generate a random token using secrets module
    token = secrets.token_urlsafe(16)
    return token

def send_reset_password_email(user_email, token):
    # Email configuration
    sender_email = os.getenv('EMAIL_USERNAME')  # Get email username from environment variable
    password = os.getenv('EMAIL_PASSWORD')  # Get email password from environment variable
    # Construct email message
    subject = "Password Reset Request"
    body = f"Please click on the following link to reset your password: http://127.0.0.1:3000/password?token={token}"
    message = MIMEMultipart()
    message['Subject'] = subject
    message['From'] = sender_email
    message['Subject'] = subject

    # Attach the body to the message
    message.attach(MIMEText(body, 'plain'))
        # Send email using SMTP over SSL

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)  # Specify your SMTP server and port with SSL
        server.login(sender_email, password)
        server.sendmail(sender_email, user_email, message.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print("An error occurred while sending email:", e)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    username = user.get('username', '')  # Get the username
    profile_picture = user.get('profile_picture', '')     
    if user:
        return render_template('profile.html', user=user, username=username, profile_picture=profile_picture)
    
    return "You need to log in first."

# Route to change username
@app.route('/username', methods=['GET', 'POST'])
def handle_change_username():
    return change_username()

# Route to change email
@app.route('/email', methods=['GET', 'POST'])
def handle_change_email():
    return change_email()

# Route to edit bio
@app.route('/bio', methods=['GET', 'POST'])
def handle_edit_bio():
    return edit_bio()

# Route to update personal information
@app.route('/personal', methods=['GET', 'POST'])
def handle_update_personal_info():
    return update_personal_info()

# Route to update profile picture
@app.route('/picture', methods=['GET', 'POST'])
def upload_picture():
    if 'user_id' not in session:
        flash('You need to log in first', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'profile_picture' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['profile_picture']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type', 'error')

    return render_template('upload_picture.html')

# Route to change password
@app.route('/password', methods=['GET', 'POST'])
def handle_change_password():
    return change_password()

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=3000)
