# Perform required imports
import os, redis
from flask import (Flask, request, session, g, redirect, url_for,
     abort, render_template, flash, send_from_directory)
from flask.ext.bcrypt import Bcrypt
from getpass import getpass
from wtforms import Form, BooleanField, TextField, PasswordField, validators


# create our little wishlist application
app = Flask(__name__)
flask_auth = Bcrypt(app)

# Load config
app.config.update(dict(
    SECRET_KEY = 'Vnd1WVe5mNfe5fgz0wwZ0NL4mNfe5fgzVnd1WVe5',
))


# Database functions
# r0 = auth database
# r1 = posts database
r0 = redis.StrictRedis(host='localhost', port=6379, db=0)
r1 = redis.StrictRedis(host='localhost', port=6379, db=1)

# Classes
class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])

class ServerError(Exception):
    pass

# Route common static files
@app.route('/robots.txt')
@app.route('/sitemap.xml')
@app.route('/favicon.ico')
def static_from_root():
    return send_from_directory('static', request.path[1:])

# Routes
@app.route('/')
def index():
    data = {}
    posts = r1.zrangebyscore('posts', '-inf', '+inf')
    for p in posts:
        data[p] = r1.hgetall(p)
    return render_template('index.html', data=data)

@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    n = r1.zcard('posts')
    p = 'post:' + n
    r1.zadd('posts', n, p)
    r1.hmset( p, { 'name' : name , 'post' : post })
    flash('New entry was successfully posted')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)

    error = None
    try:
        if request.method == 'POST':
            if r0.hget('users', 'username') != request.form['username']:
                raise ServerError('Invalid username')

            if flask_auth.check_password_hash(r0.hget('users', 'password'), request.form['password']):
                session['logged_in'] = True
                flash('Thank you for logging in.')
                return redirect(url_for('index'))

            raise ServerError('Invalid password')
    except ServerError as e:
        error = str(e)

    return render_template('login.html', form=form, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out.')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
