from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, current_user
from flask_login import UserMixin

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'cate'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db = SQLAlchemy(app)
  # Specify the login view (the route to redirect to when login is required)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
class TaskForm(FlaskForm):
    content = StringField('Task Content', validators=[DataRequired()])
    submit = SubmitField('Add Task')

@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('home.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('user'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('home'))   
    return render_template('login.html')

@app.route('/user', methods=['GET', 'POST'])
def user(): 
    user= None
    tasks = []
    form = TaskForm()

    if 'user_id' in session:
        user_id = session['user_id']  
        tasks = Task.query.filter_by(user_id=user_id).all()
        user = User.query.get_or_404(user_id)
        
        if form.validate_on_submit():
            content = form.content.data
            new_task = Task(content=content, user_id=user_id)
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully!')

    return render_template('user.html', user=user, tasks=tasks, form=form)



@app.route('/delete_task/<int:task_id>', methods=['GET', 'POST'])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('user'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out succesfully !")
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

        
        