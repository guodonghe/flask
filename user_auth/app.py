from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'abcdefg'  # 替换为安全的随机字符串

# 初始化数据库
def init_db():
    conn = sqlite3.connect('user_auth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 注册用户
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash("用户名和密码不能为空", "error")
            return redirect(url_for('register'))

        conn = sqlite3.connect('user_auth.db')
        cursor = conn.cursor()

        try:
            # 哈希密码
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            flash("注册成功，请登录", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("用户名已存在", "error")
        finally:
            conn.close()

    return render_template('register.html')

# 登录用户
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('user_auth.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()

        if row and bcrypt.checkpw(password.encode('utf-8'), row[0]):
            session['username'] = username
            flash("登录成功！", "success")
            return redirect(url_for('welcome'))
        else:
            flash("用户名或密码错误", "error")

    return render_template('login.html')

# 欢迎页面
@app.route('/welcome')
def welcome():
    if 'username' not in session:
        flash("请先登录", "error")
        return redirect(url_for('login'))

    return render_template('welcome.html', username=session['username'])

# 登出
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("已登出", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host="172.30.70.200",port=5000,debug=True)

