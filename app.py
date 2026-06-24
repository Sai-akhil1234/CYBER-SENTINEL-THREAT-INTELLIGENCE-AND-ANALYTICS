import os
import json
import numpy as np
import pandas as pd
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report

app = Flask(__name__)
app.secret_key = 'cybersentinal_secret_2026'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable static file caching
DATASET_PATH = 'dataset_sdn.csv'
USER_DB = 'users.json'
_cache = {}

def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, 'r') as f:
        try:
            return json.load(f)
        except:
            return {}

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

def compute_all_stats():
    if 'stats' in _cache:
        return _cache['stats']

    if not os.path.exists(DATASET_PATH):
        return None

    data = pd.read_csv(DATASET_PATH)

    # ── 1. Label Counts ───────────────────────────────────────────────────────
    label_counts = data['label'].value_counts().to_dict()
    genuine = int(label_counts.get(0, 0))
    malicious = int(label_counts.get(1, 0))

    # ── 2. Protocols (All vs Malicious) ───────────────────────────────────────
    proto_all = {str(k): int(v) for k, v in data['Protocol'].value_counts().to_dict().items()}
    proto_mal = {str(k): int(v) for k, v in data[data['label'] == 1]['Protocol'].value_counts().to_dict().items()}
    for p in proto_all:
        proto_mal.setdefault(p, 0)

    # ── 3. Source IPs Top 10 ──────────────────────────────────────────────────
    src_all = {str(k): int(v) for k, v in data['src'].value_counts().head(10).to_dict().items()}
    src_mal = {str(k): int(v) for k, v in data[data['label'] == 1]['src'].value_counts().head(10).to_dict().items()}

    # ── 4. Null Values ────────────────────────────────────────────────────────
    null_vals = {str(k): int(v) for k, v in data.isnull().sum().to_dict().items()}

    # ── 5. Data Describe ──────────────────────────────────────────────────────
    df_clean = data.dropna()
    numeric_df = df_clean.select_dtypes(include=['int64', 'float64'])
    desc_raw = numeric_df.describe().round(4)
    # Convert to: { "col1": {"count": X, "mean": Y, ...}, ... }
    describe = {}
    for col in desc_raw.columns:
        describe[col] = {stat: round(float(val), 4) for stat, val in desc_raw[col].to_dict().items()}

    # ── 6. ML Models ─────────────────────────────────────────────────────────
    df_ml = df_clean.copy()
    X = df_ml.drop(['dt', 'src', 'dst', 'label'], axis=1, errors='ignore')
    y = df_ml['label']
    X = pd.get_dummies(X)
    X_scaled = preprocessing.StandardScaler().fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, random_state=42, test_size=0.3)

    # Logistic Regression
    lr = LogisticRegression(C=0.03, solver='lbfgs', max_iter=1000)
    lr.fit(X_train, y_train)
    lr_pred = lr.predict(X_test)
    lr_acc = round(accuracy_score(y_test, lr_pred) * 100, 2)
    lr_rep = classification_report(y_test, lr_pred, output_dict=True)
    lr_prec = round(float(lr_rep.get('1', lr_rep.get(1, {'.': {}})).get('precision', 0)) * 100, 2)

    # KNN
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(X_train, y_train)
    knn_pred = knn.predict(X_test)
    knn_acc = round(accuracy_score(y_test, knn_pred) * 100, 2)
    knn_rep = classification_report(y_test, knn_pred, output_dict=True)
    knn_prec = round(float(knn_rep.get('1', knn_rep.get(1, {'.': {}})).get('precision', 0)) * 100, 2)

    stats = {
        'total_records': int(len(data)),
        'labels': {'Genuine': genuine, 'Malicious': malicious},
        'before_removal': {'Malicious': malicious, 'Genuine': genuine},
        'after_removal': {'Genuine': genuine, 'Remaining_Malicious': 0},
        'protocols': {'all': proto_all, 'malicious': proto_mal},
        'src_ips': {'all': src_all, 'malicious': src_mal},
        'null_values': null_vals,
        'describe': describe,
        'models': {
            'lr': {'accuracy': lr_acc, 'precision': lr_prec},
            'knn': {'accuracy': knn_acc, 'precision': knn_prec}
        }
    }

    _cache['stats'] = stats
    return stats


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login') if 'logged_in' not in session else url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = request.form.get('remember') == 'on'
        users = load_users()
        
        if username in users and users[username] == password:
            session.permanent = remember
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    confirm = request.form.get('confirm_password', '').strip()
    
    if not username or not password:
        return render_template('login.html', error='Username and password are required', signup=True)
    
    if password != confirm:
        return render_template('login.html', error='Passwords do not match', signup=True)
    
    # Password validation: must contain letters, numbers, and special characters
    if len(password) < 6:
        return render_template('login.html', error='Password must be at least 6 characters long', signup=True)
    
    has_letter = any(c.isalpha() for c in password)
    has_number = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(c in special_chars for c in password)
    
    if not (has_letter and has_number and has_special):
        return render_template('login.html', error='Password must contain letters, numbers, and special characters', signup=True)
    
    users = load_users()
    if username in users:
        return render_template('login.html', error='Username already exists', signup=True)
    
    users[username] = password
    save_users(users)
    
    return render_template('login.html', success='Account created successfully! Please login to continue.')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    if 'logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    stats = compute_all_stats()
    if stats is None:
        return jsonify({'error': 'Dataset not found'}), 404
    result = dict(stats)
    result['username'] = session.get('username', 'User')
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
