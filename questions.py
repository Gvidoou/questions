import os
from flask import Flask, render_template, request
from flask.ext.login import LoginManager
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

app = Flask(__name__)

# main page view
@app.route('/')
def main_page():
    return render_template('main.html', title='Ask questions - get answers!')

# connecting to DB
dirpath = os.path.abspath(os.path.dirname(__file__))
engine = create_engine('sqlite:///' + dirpath + 'questions.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
# using declarative method
Base = declarative_base()
Base.query = db_session.query_property()


# user class
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String, primary_key=True)
    password = Column(String, primary_key=True)

    def __init__(self, name, password):
        self.name = name
        self.password = password

    def __repr__(self):
        return '<User %s>' % self.name

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(userid):
    return User.get(userid)

@app.route('/login')
def login():

    return ''


# decelerating models
def init_db():
    Base.metadata.create_all(bind=engine)

app.run(debug=True)