from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

application = Flask(__name__)
application.config['SECRET_KEY'] = '3oueqkfdfafdfdfkjdfkjruewqndr8ewrewrouewrere44554'
bcrypt = Bcrypt(application)

application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
application.config['SQLALCHEMY_BINDS'] ={'frase': 'sqlite:///frase.db'}
db = SQLAlchemy(application)

class User(db.Model):
  __tablename__ = "user_table"
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), unique=True, nullable=False)
  email = db.Column(db.String(120), unique=True, nullable=False)
  password = db.Column(db.String(60), nullable=False)
  frase = db.relationship('Frase', backref='author', lazy=True)

class Frase(db.Model):
  __tablename__= 'frase_table'
  id = db.Column(db.Integer, primary_key=True)
  frase = db.Column(db.String)
  user_id = db.Column(db.Integer, db.ForeignKey('user_table.id'), nullable=False)

class RegistrationForm(FlaskForm):
  username = StringField('Username', 
                         validators=[DataRequired(), Length(min=2, max=30)])
  email = StringField('Email',
                      validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password',
                      validators=[DataRequired(), EqualTo('password')])                                
  submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
  email = StringField('Email',
                      validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  remember = BooleanField('Remember Me')
  submit = SubmitField('Login') 

@application.route('/')
@application.route('/home')
def home():
  return render_template('home.html')

@application.route('/business')
def business():
  return render_template('business.html', title='business')

@application.route('/ERASMUSAL')
def ERASMUSAL():
    return render_template('ERASMUSAL.html', title='ERASMUSAL')

@application.route('/register', methods=['GET','POST'])
def register():
  form = RegistrationForm()
  if form.validate_on_submit():
      user_hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
      user = User(username=form.username.data, email=form.email.data, password=user_hashed_password)
      db.session.add(user)
      db.session.commit()
      flash('¡Tu cuenta ha sido creada! ¡Ahora puedes iniciar sesión!', 'success')
      return redirect(url_for('login'))
  return render_template('register.html', title='register', form=form)

@application.route('/login', methods=['GET','POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user and bcrypt.check_password_hash(user.password, form.password.data):
        flash('¡Has iniciado sesión! ¡Ahora puedes empezar a utilizar nuestra aplicación Light Talk!', 'success')
        return redirect(url_for('home'))
    else:
        flash('No se pudo iniciar sesión. ¡Verifique su correo electrónico y contraseña!', 'danger') 
  return render_template('login.html', title='login', form=form)

if __name__=='__main__':
  application.run(debug=True)  