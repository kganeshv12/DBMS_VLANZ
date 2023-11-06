from flask import Flask, redirect, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.debug = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

migrate = Migrate(app, db)

class Profile(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(20), unique=False, nullable=False)
	last_name = db.Column(db.String(20), unique=False, nullable=False)
	age = db.Column(db.Integer, nullable=False)

	def __repr__(self):
		return f"Name : {self.first_name}, Age: {self.age}"
	
class Freelancer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"Name: {self.name}, Domain: {self.domain}, Description: {self.description}"
    
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    orders = db.relationship('Orders', backref='user', lazy=True)
    num_orders = db.Column(db.Integer, default=0)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('customer', 'Customer'), ('freelancer', 'Freelancer')], validators=[DataRequired()])
    submit = SubmitField('Register')

class Orders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    freelancer_id = db.Column(db.Integer, db.ForeignKey('freelancer.id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    freelancer = db.relationship('Freelancer', backref='orders')

    def __repr__(self):
        return f"Order ID: {self.id}, User ID: {self.user_id}, Freelancer ID: {self.freelancer_id}"
    
class AddServiceForm(FlaskForm):
    name = StringField('Freelancer Name', validators=[DataRequired()])
    domain = StringField('Service Domain', validators=[DataRequired()])
    description = TextAreaField('Service Description', validators=[DataRequired()])
    submit = SubmitField('Add Service')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    profiles = Profile.query.all()
    if current_user.role == 'customer':
        purchased_services = [order.freelancer_id for order in current_user.orders]
        freelancers = Freelancer.query.filter(Freelancer.id.notin_(purchased_services)).all()
        return render_template('customer_page.html', profiles=profiles, freelancers=freelancers)
    elif current_user.role == 'freelancer':
        freelancers = Freelancer.query.all()
        return render_template('freelancer_page.html', profiles=profiles, freelancers=freelancers)
	
@app.route('/delete/<int:id>')
def erase(id):
    data = Profile.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/')

@app.route('/delete_freelancer/<int:id>')
def delete_freelancer(id):
    freelancer = Freelancer.query.get(id)
    if freelancer:
        db.session.delete(freelancer)
        db.session.commit()
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect('/')
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data 

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Choose a different one.', 'danger')
        else:
            user = User(username=username, password_hash=generate_password_hash(password), role=role)  
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect('/login')
    return render_template('register.html', form=form)

@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if current_user.role == 'freelancer':
        form = AddServiceForm() 
        if form.validate_on_submit():
            name = form.name.data
            domain = form.domain.data
            description = form.description.data

            if name and domain and description:
                freelancer = Freelancer(name=name, domain=domain, description=description)
                db.session.add(freelancer)
                db.session.commit()
                flash('Service added successfully!', 'success')
                return redirect(url_for('home'))  
        return render_template('add_service.html', form=form)
    return redirect('/')

@app.route('/logout', methods=['GET']) 
@login_required
def logout():
    logout_user()
    return redirect('/login')

from sqlalchemy import func

@app.route('/buy/<int:freelancer_id>', methods=['POST'])
@login_required
def buy(freelancer_id):
    user_id = current_user.id
    existing_order = Orders.query.filter_by(user_id=user_id, freelancer_id=freelancer_id).first()
    if existing_order:
        flash('You have already purchased this service.', 'warning')
    else:
        order = Orders(user_id=user_id, freelancer_id=freelancer_id)
        db.session.add(order)
        db.session.commit()
        flash('Service purchased successfully!', 'success')
    return redirect('/')

if __name__ == '__main__':
    app.config['SECRET_KEY'] = 'vlanz'
    with app.app_context():
        db.create_all()    
    app.run()
