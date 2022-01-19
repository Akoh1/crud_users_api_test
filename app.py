from flask import Flask, request, Response, jsonify, make_response, redirect, render_template, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from decouple import config
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
# import datetime

# from flask.ext.mail import Message
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer



app = Flask(__name__)

# from token import generate_confirmation_token, confirm_token



# app.config.from_object(os.environ['APP_SETTINGS'])
# app.config.from_object(config('APP_SETTINGS'))
app.config.from_object("config.DevelopmentConfig")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
mail = Mail(app)

from models import User


# route to get all movies
@app.route("/")
def hello():
    return "Hello World!"

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    print(f'serializer {serializer}')
    email = None
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    print(f'token email: {email}')
    return email

@app.route('/confirm/<token>')
def confirm_email(token):
    email = None
    try:
        email = confirm_token(token)
    except:
        print("No token working")
        flash('The confirmation link is invalid or has expired.', 'danger')
        return render_template('confirmed_error.html')
    user = User.query.filter_by(email=email).first_or_404()
    if user.activated:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.activated = True
        user.activated_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        print('Email confirmed')
        flash('You have confirmed your account. Thanks!', 'success')
    # return redirect("127.0.0.1:3000/users", code=302)
    return render_template('confirmed.html')

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        print("token: {}".format(token))
        print("Sec Key: {}".format(app.config['SECRET_KEY']))
        # data = jwt.decode(token, app.config['SECRET_KEY'])
        # print("Data {}".format(data))
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print("Data {}".format(data))
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

# User Database Route
# this route sends back list of users users
@app.route('/users', methods =['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    print(f"Current User {current_user}")
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'first_name' : user.first_name,
            'last_name' : user.last_name,
            'full_name': user.full_name(),
            'standard_user' : user.standard_user,
            'admin_user' : user.admin_user,
            'email' : user.email,
            'activated': user.activated
        })
  
    return jsonify({'users': output})

@app.route('/users/<string:public_id>', methods =['GET'])
@token_required
def get_user(current_user, public_id):
    print(f"Get user public id: {public_id}")
    return_value = User.get_user(public_id)
    return jsonify(return_value)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
    print(f"Signup Data {data}")
    # gets name, email and password
    first_name, last_name, email = data.get('first_name'), \
        data.get('last_name'), data.get('email')
    password = data.get('password')
    standard = False
    admin = False
    if 'standard_user' in data:
        standard = True
    if 'admin_user' in data:
        admin = True
  
    # checking for existing user
    user = User.query\
        .filter_by(email = email)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            first_name = first_name,
            last_name = last_name,
            email = email,
            password = generate_password_hash(password),
            standard_user = standard,
            admin_user = admin
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate_mail.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, html)
  
        return make_response('Successfully registered, A confirmation email has been sent via email', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
  
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes=120)
        }, app.config['SECRET_KEY'], "HS256")

        User.add_token(user.email, token)
  
        return make_response(jsonify({'token' : token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

@app.route('/user/<string:public_id>', methods=["PATCH"])
@token_required
def update_user(current_user, public_id):
    data = request.form
    print(f'Update data: {data}')
    request_data = request.get_json()  # getting data from client
    print('Res Data: {}'.format(request_data))
    print('request: {}'.format(request))
    if public_id:
        update = User.query.filter_by(public_id=public_id).first()
        if data:
            # for key, val in data.items():
            #     print(f'key: {key}, val: {val}')
            #     if 'standard_user' != key or 'admin_user' != key:
            #         update.key = val
            if 'first_name' in data:
                update.first_name = data.get('first_name')
            if 'last_name' in data:
                update.first_name = data.get('last_name')
            if 'password' in data:
                update.password = generate_password_hash(data.get('password'))
            if 'activated' in data:
                update.activated = data.get('activated')
            if 'photo' in data:
                update.activated = data.get('photo')
            if 'standard_user' in data:
                update.standard_user = True
            if 'admin_user' in data:
                update.admin_user = True
            db.session.commit()
            return make_response('Successfully Updated.', 201)
        else:
            return make_response('Request Data not found.', 404)
    
    return make_response(
        'No public Id for user',
        401
    )


if __name__ == '__main__':
    app.run()
