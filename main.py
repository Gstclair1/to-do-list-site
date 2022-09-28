from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditor
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    to_do_items = db.Column(db.String(5000))

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/todo")
@app.route('/')
def home():
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        to_do = user.to_do_items
        try:
            if len(to_do) > 0:
                task_list = to_do.strip("["", ]""'"",").split("', '")
        except TypeError:
            task_list = []
    else:
        task_list = []
    return render_template('index.html', items=task_list)


@app.route('/<items>')
def home_items(items):
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        to_do = user.to_do_items
        try:
            if len(to_do) > 0:
                task_list = to_do.strip("["", ]""'"",").split("', '")
        except TypeError:
            task_list = []
    else:
        task_list = items.strip("["", ]""'"",").split("', '")
    return render_template('index.html', items=task_list)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/add/<task_list>', methods=["GET", "POST"])
def add_item(task_list):
    item = request.form["new_list_item"]
    new_task_list = task_list.strip("[""]""'"",").split("', '")
    new_task_list.append(item)
    if current_user.is_authenticated:
        string = "["
        for item in new_task_list:
            string += "'" + item + "', "
        string += "]"
        print(string)
        user = User.query.get(current_user.id)
        user.to_do_items = string
        db.session.commit()

    return redirect(url_for('home_items', items=new_task_list))


@app.route('/done/<item>-<task_list>', methods=["GET","POST"])
def done(item, task_list):
    new_task_list = task_list.strip("[""]""'"",").split("', '")
    item_to_remove = new_task_list.index(item)
    new_task_list.remove(new_task_list[item_to_remove])
    if current_user.is_authenticated:
        string = "["
        for item in new_task_list:
            string += "'" + item + "', "
        string += "]"
        print(string)
        user = User.query.get(current_user.id)
        user.to_do_items = string
        db.session.commit()
    return redirect(url_for('home_items', items=new_task_list))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
