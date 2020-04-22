#Application to log in and create lists of favorite restaurants using YelpAPI

#############################
### SI 364: Final Project ###
### Nicolas Ortega | F18 ####
#############################

# Import statements
import os
import re
import requests
import json
from yelpapi import YelpAPI
from prettyprinter import pprint

# from giphy_api_key import api_key #do this for yelp api_key as well?
MY_API_KEY = ""

from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import PrimaryKeyConstraint, ForeignKeyConstraint, Sequence
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/nortegagProjectDB" #create database in terminal before running
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# App addition setups
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

########################
######## Models ########
########################

##Association Table

#between business and lists
user_list = db.Table('user_list', db.Column('business_id', db.String(64), db.ForeignKey('business.id')), db.Column('list_id', db.Integer, db.ForeignKey('resList.id')))


## User model for login (from HW4)
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(240), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128), unique=True, index=True)
    # establishing user relationship with lists
    lists = db.relationship('RestaurantList', backref='User')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

## DB load function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) #returns User object or None


class Business(db.Model):
    __tablename__ = "business"
    # id = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.String(64), primary_key=True, unique=False)
    name = db.Column(db.String(255))
    type = db.Column(db.String(128))
    url = db.Column(db.String(255))
    rating = db.Column(db.Float)
    coordinates = db.Column(db.String(255)) #need to convert the returning dict to string
    price = db.Column(db.String(10))
    address = db.Column(db.String(255)) # convert list to string (use display_address)
    location = db.Column(db.String(128))
    phone = db.Column(db.String(25))


class Reviews(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    #one business, many reviews
    business_id = db.Column(db.String(255), db.ForeignKey('business.id'))
    text = db.Column(db.String())
    rating = db.Column(db.Float)
    review_url = db.Column(db.String(255))


class RestaurantList(db.Model):
    __tablename__ = "resList"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))

    #one-to-many with User model
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    #many-to-many with the Business model (one business might be in many restaurant_lists, one restaurant_list could have many businesses)
    businesses = db.relationship('Business', secondary=user_list, backref=db.backref('RestaurantList', lazy='dynamic'), lazy='dynamic')


########################
######## Forms #########
########################

# Provided
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')


# Provided
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RestaurantSearchForm(FlaskForm):
    food_type = StringField('What do you wanna eat? ', validators=[Required()])
    location = StringField('Where? ', validators=[Required()])
    submit = SubmitField("Let's eat!")

    def food_type_validator(self, field):
        if not re.search('\w+', field.data):
            raise ValidationError("That can't be a food type!")


    def location_validator(self, field):
        if len(field.data) < 2:
            raise ValidationError("Is that a location? Specify as much as you can.")


class RestaurantListCreateForm(FlaskForm):
    name = StringField('List name:', validators=[Required()])
    restaurant_picks = SelectMultipleField('Pick your restaurants!') # *** track how this works
    submit = SubmitField('Submit')

class UpdateButtonForm(FlaskForm):
    submit = SubmitField('Update')

class UpdateListName(FlaskForm):
    new_name = StringField('Enter new name for list: ', validators=[Required()])
    submit = SubmitField('Update Name')

class DeleteButtonForm(FlaskForm):
    submit = SubmitField('Delete')


########################
### Helper functions ###
########################

def get_business_by_id(id):
    #use to create lists later !
    b = Business.query.filter_by(id=id).first()
    return b

def get_restaurants_and_reviews_from_yelp(type, location): #0=restaurants, 1=reviews ##change to just get_restaurants?
    yelp_api = YelpAPI(MY_API_KEY)
    rests = yelp_api.search_query(term=type, location=location, limit=5)
    restaurants = rests['businesses']

    restaurant_ids = []
    reviews = []

    for x in restaurants:
        id = x['id']
        restaurant_ids.append(id)

    for d in restaurant_ids:
        # reviews = []
        review = yelp_api.reviews_query(id=d)

        for r in review['reviews']:
            reviews.append(r)

    return restaurants, reviews



def get_or_create_business_and_reviews(type, location):
    business = db.session.query(Business).filter_by(type=type, location=location).first()

    if business:
        return business

    else:
        res = get_restaurants_and_reviews_from_yelp(type, location)
        for entry in res[0]:

            if 'price' not in entry:
                business = Business(
                id=entry['id'],
                type=type,
                name=entry['name'],
                url=entry['url'],
                rating=entry['rating'],
                coordinates=str(entry['coordinates']),
                price = 'N/A',
                address=str(entry['location']['display_address']),
                location=location,
                phone=entry['phone'])


            else:
                business = Business(
                id=entry['id'],
                type=type,
                name=entry['name'],
                url=entry['url'],
                rating=entry['rating'],
                coordinates=str(entry['coordinates']),
                price = entry['price'],
                address=str(entry['location']['display_address']),
                location=location,
                phone=entry['phone'])


            db.session.add(business)
            db.session.commit()


        ## now getting list of ids to assign
        businessids = db.session.query(Business.id).filter_by(type=type, location=location).all()

        bids = [r.id for r in businessids] #list comp to get ids, assign to correct review

        #doing for loops for every three reviews
        for r in res[1][:3]: #res[1] is a list of dictionaries
            data = r['text']

            reviews = Reviews(
            business_id=bids[0],
            text=data,
            rating=r['rating'],
            review_url=r['url']
            )

            db.session.add(reviews)
            db.session.commit() ## adding all reviews to the one business_id

        for r in res[1][3:6]: #res[1] is a list of dictionaries
            data = r['text']

            reviews = Reviews(
            business_id=bids[1],
            text=data,
            rating=r['rating'],
            review_url=r['url']
            )

            db.session.add(reviews)
            db.session.commit() ## adding all reviews to the one business_id


        for r in res[1][6:9]: #res[1] is a list of dictionaries
            data = r['text']

            reviews = Reviews(
            business_id=bids[2],
            text=data,
            rating=r['rating'],
            review_url=r['url']
            )

            db.session.add(reviews)
            db.session.commit() ## adding all reviews to the one business_id


        for r in res[1][9:12]: #res[1] is a list of dictionaries
            data = r['text']

            reviews = Reviews(
            business_id=bids[3],
            text=data,
            rating=r['rating'],
            review_url=r['url']
            )

            db.session.add(reviews)
            db.session.commit() ## adding all reviews to the one business_id

        for r in res[1][12:15]: #res[1] is a list of dictionaries
            data = r['text']

            reviews = Reviews(
            business_id=bids[4],
            text=data,
            rating=r['rating'],
            review_url=r['url']
            )

            db.session.add(reviews)
            db.session.commit() ## adding all reviews to the one business_id

        # print(bids) #list of objects, just need the last one (with all id's) [4]
        # print(len(res[1][:3])) #15

        return business

def get_or_create_list(name, user_id, business_list=[]):
    list = db.session.query(RestaurantList).filter_by(name=name, user_id=current_user.id).first()
    if list:
        return list

    else:
        list = RestaurantList(name=name, user_id=current_user.id, businesses=[])
        for b in business_list:
            list.businesses.append(b)

        db.session.add(list)
        db.session.commit()

        return list


########################
#### View functions ####
########################

## Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


## Login-related routes - provided
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


@app.route('/', methods=['GET','POST'])
def index():
    form = RestaurantSearchForm()
    if form.validate_on_submit():
        get_or_create_business_and_reviews(type=form.food_type.data, location=form.location.data)
        return redirect(url_for('search_results', food_type=form.food_type.data, location=form.location.data))


    return render_template('index.html', form=form)

@app.route('/top_restaurants/<food_type>/<location>') #other routes to add /location/food_type
def search_results(food_type, location):
    location = location
    food_type = food_type
    rests = Business.query.filter_by(type=food_type, location=location).all()

    return render_template('type_restaurants.html', restaurants=rests, location=location, food_type=food_type)

@app.route('/all_businesses')
def all_businesses():
    businesses = Business.query.all()

    return render_template('all_businesses.html', businesses=businesses)

@app.route('/create_list', methods=["GET","POST"])
@login_required
def create_list():
    form = RestaurantListCreateForm()
    busi = Business.query.all()
    choices =  [(b.id, b.name) for b in busi]
    form.restaurant_picks.choices = choices

    if request.method == "POST":
        businesses = []
        for pick in form.restaurant_picks.data:
            businesses.append(get_business_by_id(pick))

        get_or_create_list(form.name.data, current_user, businesses)

        return redirect(url_for('lists'))
    else:
        return render_template('create_list.html', form=form)


@app.route('/lists', methods=["GET","POST"])
@login_required
def lists():
    form = DeleteButtonForm()
    lists = RestaurantList.query.filter_by(user_id=current_user.id).all()

    return render_template('lists.html', lists=lists, form=form)

@app.route('/list/<id_val>')
def only_list(id_val):
    form = UpdateButtonForm()
    list = RestaurantList.query.filter_by(id=id_val).first()
    print(list)
    rests = list.businesses.all()

    return render_template('single_list.html', list=list, rests=rests, form=form)

@app.route('/update/<den>', methods=["GET","POST"])
def update(den):
    form = UpdateListName()
    if form.validate_on_submit():
        d = RestaurantList.query.filter_by(id=den).first()
        d.name = form.new_name.data
        db.session.commit()
        flash("Name updated")
        return redirect(url_for('lists'))

    return render_template('update_name.html', den=den, form=form)

@app.route('/delete/<list>', methods=["GET","POST"])
def delete(list):
    ls = RestaurantList.query.filter_by(id=list).first()
    db.session.delete(ls)
    db.session.commit()
    flash('Deleted list')

    return redirect(url_for('lists'))



if __name__ == '__main__':
    db.create_all()
    manager.run()
