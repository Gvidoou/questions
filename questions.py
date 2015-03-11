from flask import Flask, render_template, url_for, flash, request, redirect, g
from flask.ext.login import LoginManager, login_user, current_user, logout_user, \
    login_required
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from wtforms import StringField, PasswordField, validators, TextAreaField
from flask.ext.wtf import Form
app = Flask(__name__)
app.config.update(
    CSRF_ENABLED=True,
    DEBUG=True,
    SECRET_KEY='secret key',
)

# All db configurations

# connecting to DB
engine = create_engine('sqlite:///' + app.root_path + 'questions.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
# using declarative method
Base = declarative_base()
Base.query = db_session.query_property()


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


# All models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    password = Column(String)
    asked_questions = relationship('Questions')
    answers = relationship('Answers')
    like = relationship('Like')

    def __init__(self, name, password):
        self.name = name
        self.password = password

    def __repr__(self):
        return '<User %s>' % self.name

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)


class Questions(Base):
    __tablename__ = 'questions'
    id = Column(Integer, primary_key=True)
    question = Column(String)
    details = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    answers = relationship('Answers')

    def __init__(self, details, question, user_id):
        self.details = details
        self.question = question
        self.user_id = user_id

    def get_user(self):
        return User.query.filter_by(id=self.user_id).first().name


class Answers(Base):
    __tablename__ = 'answers'
    id = Column(Integer, primary_key=True)
    answer = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    question_id = Column(Integer, ForeignKey('questions.id'), nullable=False)
    like = relationship('Like')
    likes = Column(Integer)

    def __init__(self, answer, user_id, question_id):
        self.answer = answer
        self.user_id = user_id
        self.question_id = question_id
        self.likes = 0

    def get_user(self):
        return User.query.filter_by(id=self.user_id).first().name


class Like(Base):
    __tablename__ = 'likes'
    id = Column(Integer, primary_key=True)
    answer = Column(Integer, ForeignKey('answers.id'), nullable=False)
    user = Column(Integer, ForeignKey('users.id'), nullable=False)

    def __init__(self, answer, user):
        self.answer = answer
        self.user = user


# login settings
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))


# Forms
class AddQuestionForm(Form):
    question = StringField('Question', validators=[validators.length(3, 30)])
    details = TextAreaField('Description', validators=[validators.optional()])


class LoginForm(Form):
    name = StringField('Login', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])


class AnswerForm(Form):
    answer = TextAreaField('Answer', validators=[validators.length(3)])


@app.before_request
def before_request():
    g.user = current_user


# All views
@app.route('/')
def main_page():
    questions = Questions.query.all()
    return render_template('main.html', title='Ask questions - get answers!',
                           questions=questions)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_question():
    form = AddQuestionForm()
    if request.method == 'POST' and form.validate():
        user_id = g.user.id
        question = request.form['question']
        details = request.form['details']
        new_question = Questions(question=question, details=details,
                                 user_id=user_id)
        db_session.add(new_question)
        db_session.commit()
        flash('Your question successfully submitted!')
        return redirect(url_for('main_page'))
    return render_template('add_question.html', title='Add question', form=form)



@app.route('/answer/<question_id>', methods=['GET', 'POST'])
@login_required
def answer(question_id):
    form = AnswerForm()
    question = Questions.query.filter_by(id=question_id).first()
    if not question:
        flash('Looks like this question is not available')
        return redirect(url_for('main_page'))
    if request.method == 'POST' and form.validate():
        answer_text = request.form['answer']
        user = g.user.id
        answer = Answers(answer_text, user, question.id)
        db_session.add(answer)
        db_session.commit()
        flash('Your answer successfully submitted')
        return redirect(url_for('main_page'))
    return render_template('answers.html', title='Add answer',
                           question=question, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if g.user.is_authenticated():
        return redirect(url_for('main_page'))

    if request.method == 'POST':
        # login and validate the user...
        if form.validate():
            name = request.form['name']
            password = request.form['password']
            user = User.query.filter_by(name=name, password=password).first()
            if user is None:
                flash('Wrong data, try again')
                return redirect(url_for('login'))
            login_user(user)
            flash("Logged in successfully.")
            return redirect(url_for('main_page'))
    return render_template("login_form.html", form=form, title='Sign In')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = LoginForm()
    if g.user.is_authenticated():
        return redirect(url_for('main_page'))

    if request.method == 'POST' and form.validate():
        name = request.form['name']
        password = request.form['password']
        if not User.query.filter_by(name=name).first():
            user = User(name, password)
            db_session.add(user)
            db_session.commit()
            flash("You have successfully registered. Now you can log in.")
            return redirect(url_for('login'))
        else:
            flash('This name already used. Please try again.')
            return render_template('login_form.html',
                                   form=form,
                                   title='Sign up')
    return render_template('login_form.html', form=form, title='Sign up')


@app.route('/logout')
def logout():
    logout_user()
    flash('You are logged out.')
    return redirect(url_for('main_page'))


@app.route('/like/<answer_id>')
@login_required
def like(answer_id):
    user = g.user.id
    answer = Answers.query.filter_by(id=answer_id).first()
    if Like.query.filter_by(user=user, answer=answer_id).first():
        flash('Already voted')
        return redirect(url_for('main_page'))
    elif answer:
        vote = Like(answer=answer_id, user=user)
        db_session.add(vote)
        answer.likes += 1
        db_session.commit()
        flash("You'r vote successfully submitted")
        return redirect(url_for("main_page"))
    else:
        flash('This answer not available for voting')
        return redirect(url_for('main_page'))


# decelerating models
def init_db():
    Base.metadata.create_all(bind=engine)

init_db()
app.run(debug=True)