from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure key

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view

# Dummy User Database (Replace with a real database)
users = {
    'user1': {'password': generate_password_hash('password1'), 'name': 'User One'},
    'user2': {'password': generate_password_hash('password2'), 'name': 'User Two'}
}

# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, id, name):
        self.id = id
        self.name = name

# Load User Callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id, users[user_id]['name'])
    return None

# Load MovieLens Dataset
movies = pd.read_csv('movies.csv')
ratings = pd.read_csv('ratings.csv')

# Merge the datasets
movie_ratings = pd.merge(ratings, movies, on='movieId')

# Create a user-item matrix
user_item_matrix = movie_ratings.pivot_table(index='userId', columns='title', values='rating').fillna(0)

# Calculate cosine similarity
cosine_sim = cosine_similarity(user_item_matrix)

# Function to get recommendations
def get_recommendations(user_id, num_recommendations=5):
    user_index = user_item_matrix.index.get_loc(user_id)
    user_similarity = cosine_sim[user_index]
    similar_users = user_similarity.argsort()[-num_recommendations-1:-1][::-1]
    recommendations = user_item_matrix.iloc[similar_users].mean(axis=0).sort_values(ascending=False)
    return recommendations.index.tolist()[:num_recommendations]

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username, users[username]['name'])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name)

@app.route('/recommend', methods=['POST'])
@login_required
def recommend():
    user_id = int(request.form['user_id'])
    recommendations = get_recommendations(user_id)
    return render_template('recommendations.html', recommendations=recommendations)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        if username not in users:
            users[username] = {'password': generate_password_hash(password), 'name': name}
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        flash('Username already exists.', 'error')
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)