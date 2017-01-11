from flask import (
    Flask,
    request,
    session,
    g,
    render_template,
    redirect,
    abort,
    make_response,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests


app = Flask(__name__)
app.config.from_object('config.default')
app.config.from_object('config.secret')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255))

    name = db.Column(db.String(80))

    facebook_connect = db.relationship('FacebookConnect',
                                       backref=db.backref('user',
                                                          lazy='joined',
                                                          uselist=False),
                                       lazy='joined',
                                       uselist=False)


class FacebookConnect(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

    facebook_id = db.Column(db.String(80), unique=True)
    facebook_token = db.Column(db.String(255))


@app.before_request
def before_request():
    if 'user_id' in session:
        g.user = User.query.filter_by(id=session['user_id']).one()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    alert = None
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if (not user or
            not check_password_hash(user.password, request.form['password'])):
            alert = '이메일 또는 비밀번호가 잘못되었습니다.'
        else:
            session['user_id'] = user.id

            response = make_response(redirect(url_for('index')))
            if 'remember-me' in request.form:
                response.set_cookie('email', request.form['email'])
            else:
                response.set_cookie('email', '', expires=0)
            return response

    return render_template('signin.html', alert=alert)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    alert = None
    if request.method == 'POST':
        # Check email existance
        if User.query.filter_by(email=request.form['email']).count() > 0:
            alert = '이미 사용중인 이메일입니다.'
        else:
            # Create User
            user = User()
            user.email = request.form['email']
            user.password = generate_password_hash(request.form['password'])
            user.name = request.form['name']

            db.session.add(user)
            db.session.commit()

            # Login
            session['user_id'] = user.id
            return redirect(url_for('index'))

    return render_template('signup.html', alert=alert)


@app.route('/user/me')
def my_profile():
    if not 'user_id' in session:
        return abort(401)

    return redirect(url_for('profile', user_id=session['user_id']))


@app.route('/user/<int:user_id>')
def profile(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return abort(404)

    return render_template('profile.html', user=user)


@app.route('/facebook-login')
def facebook_login():
    return redirect('https://www.facebook.com/v2.8/dialog/oauth' \
                    '?client_id={0}&redirect_uri={1}&scope={2}' \
                    .format(app.config['FACEBOOK_CLIENT_ID'],
                            app.config['FACEBOOK_REDIRECT_URI'],
                            app.config['FACEBOOK_LOGIN_SCOPE']))


@app.route('/facebook-signup', methods=['POST'])
def facebook_signup():
    # Retrieve User Information
    url = 'https://graph.facebook.com/v2.8/me'
    payload = dict(
        access_token=request.form['facebook_token'],
        fields="id,name,email"
    )
    response = requests.get(url, params=payload)
    result = response.json()

    # Check user existance
    connect = FacebookConnect.query.filter_by(facebook_id=result['id']).first()
    if connect:
        # Already signed up
        return abort(403)

    # Check email existance
    if User.query.filter_by(email=request.form['email']).count() > 0:
        return '이미 해당 이메일로 가입한 유저가 있습니다. (TODO: 통합절차)', 400

    # Create User
    user = User()
    user.email = request.form['email']
    user.password = generate_password_hash(request.form['password'])
    user.name = result['name']

    # Create FacebookConnect
    connect = FacebookConnect()
    connect.id = user.id
    connect.facebook_id = result['id']
    connect.facebook_token = request.form['facebook_token']
    user.facebook_connect = connect

    db.session.add(user)
    db.session.commit()

    # Login
    session['user_id'] = user.id
    return redirect(url_for('index'))


@app.route('/auth/callback')
def facebook_callback():
    code = request.args.get('code')

    # Retrieve Token
    url = 'https://graph.facebook.com/v2.8/oauth/access_token'
    payload = dict(
        client_id=app.config['FACEBOOK_CLIENT_ID'],
        client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
        redirect_uri=app.config['FACEBOOK_REDIRECT_URI'],
        code=code
    )
    response = requests.get(url, params=payload)
    result = response.json()
    token = result['access_token']

    # Retrieve User Information
    url = 'https://graph.facebook.com/v2.8/me'
    payload = dict(
        access_token=token,
        fields="id,name,email"
    )
    response = requests.get(url, params=payload)
    result = response.json()

    # Check user existance
    connect = FacebookConnect.query.filter_by(facebook_id=result['id']).first()

    if connect is None:
        # Redirect to Facebook signup process
        return render_template('additional_info.html',
                               email=result['email'],
                               facebook_token=token)

    # Update Token
    user = connect.user
    user.facebook_token = token

    db.session.add(user)
    db.session.commit()

    # Login
    session['user_id'] = user.id

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user_id', False)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
