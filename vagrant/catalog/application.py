from flask import Flask, render_template, request, redirect, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from model import Base, User, Category, Stuff

from flask import session as login_session
from flask import make_response, abort
import random, string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2, requests, json

from flask import jsonify

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Udacity Stuff Catalog App"

engine = create_engine('sqlite:///stuff.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# login functionality
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if (user_id == None):
        # Create a new one
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User helper functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # delete google-specific login session info
    del login_session['access_token']
    del login_session['gplus_id']

    # delete our user's login session info
    del login_session['provider']
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    # send the good response
    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    flash("You have successfully been logged out.")
    return redirect(url_for('showCategoriesAndStuff'))

# CRUD Functionality
@app.route('/')
def showCategoriesAndStuff():
    # show stuff, whether we're logged in or not
    categories = session.query(Category).order_by(asc(Category.name))
    stuff = session.query(Stuff).order_by(asc(Stuff.name))

    if 'username' not in login_session:
        # Create anti-forgery state token in case user wants to log in
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
            for x in xrange(32))
        login_session['state'] = state

        return render_template('publicCategoriesAndStuff.html', categories=categories,
            stuff=stuff, STATE=state)
    else:
        return render_template('privateCategoriesAndStuff.html', categories=categories,
            stuff=stuff, username=login_session['username'], picture=login_session['picture'])

# Read Catgegories
@app.route('/categories/<category_name>')
def showCategory(category_name):
    my_category = session.query(Category).filter(Category.name == category_name).one_or_none()
    if my_category == None:
        flash('Category %s doesn\'t exist.' % request.form['name'])
        return redirect(url_for('showCategoriesAndStuff'))
    else:
        stuff_in_category = session.query(Stuff).filter(Stuff.category_name == category_name).all()
        if 'user_id' not in login_session or login_session['user_id'] != my_category.user_id:
            return render_template('publicCategory.html', category=category_name, stuff=stuff_in_category)
        else:
            return render_template('privateCategory.html', category=category_name, stuff=stuff_in_category)

# Create Categories
@app.route('/categories/new', methods=['GET', 'POST'])
def createNewCategory():
    if 'user_id' not in login_session:
        return abort(404)
    else:
        if request.method == 'POST':
            if session.query(Category).filter(Category.name == request.form['name']).one_or_none() == None:
                newCategory = Category(name=request.form['name'], user_id=login_session['user_id'])
                session.add(newCategory)
                session.commit()
                flash('New Category %s created successfully' % newCategory.name)
                return redirect(url_for('showCategoriesAndStuff'))
            else:
                flash('Category %s already exists' % request.form['name'])
                return redirect(url_for('showCategoriesAndStuff'))
        else:
            return render_template('newCategory.html')

# Delete Categories
@app.route('/categories/<category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'user_id' not in login_session:
        return abort(404)
    else:
        category = session.query(Category).filter(Category.name == category_name).one_or_none()
        if category == None:
            abort(404)
        elif login_session['user_id'] != category.user_id:
            abort(404)
        elif session.query(Stuff).filter(Stuff.category_name == category.name).one_or_none() != None:
            flash('Category is not empty. Delete or edit the stuff that is currently categoriezed under \'%s\'.' % category.name)
            return redirect(url_for('showCategoriesAndStuff'))
        elif request.method == 'POST':
            session.delete(category)
            session.commit()
            flash('Category \'%s\' deleted.' % category.name)
            return redirect(url_for('showCategoriesAndStuff'))
        else:
            return render_template('deleteCategory.html', category=category_name)

# Read Stuff
@app.route('/stuff/<int:stuff_id>/')
def showStuff(stuff_id):
    my_stuff = session.query(Stuff).filter(Stuff.id == stuff_id).one_or_none()
    if my_stuff == None:
        abort(404)
    else:
        if 'user_id' not in login_session or login_session['user_id'] != my_stuff.user_id:
            return render_template('publicStuff.html', stuff=my_stuff)
        else:
            return render_template('privateStuff.html', stuff=my_stuff)

# Create Stuff
@app.route('/stuff/new', methods=['GET', 'POST'])
def createNewStuff():
    if 'user_id' not in login_session:
        return abort(404)
    else:
        if request.method == 'POST':
            newStuff = Stuff(name=request.form['name'],
                description=request.form['description'],
                category_name=request.form['category'],
                user_id=login_session['user_id'])
            session.add(newStuff)
            session.commit()
            flash('New Stuff %s created successfully' % newStuff.name)
            return redirect(url_for('showCategoriesAndStuff'))
        else:
            return render_template('newStuff.html')

# Update Stuff
@app.route('/stuff/<int:stuff_id>/edit/', methods=['GET', 'POST'])
def updateStuff(stuff_id):
    my_stuff = session.query(Stuff).filter(Stuff.id == stuff_id).one_or_none()
    if my_stuff == None:
        abort(404)
    elif 'user_id' not in login_session or login_session['user_id'] != my_stuff.user_id:
        abort(404)
    elif request.method == 'POST':
        my_stuff.name = request.form['name']
        my_stuff.description = request.form['description']
        my_stuff.category_name = request.form['category']
        session.add(my_stuff)
        session.commit()
        flash ('Stuff %s updated' % my_stuff.name)
        return redirect(url_for('showStuff', stuff_id=stuff_id))
    else:
        return render_template('updateStuff.html', stuff=my_stuff)

# Delete Stuff
@app.route('/stuff/<int:stuff_id>/delete/', methods=['GET', 'POST'])
def deleteStuff(stuff_id):
    my_stuff = session.query(Stuff).filter(Stuff.id == stuff_id).one_or_none()
    if my_stuff == None:
        abort(404)
    elif 'user_id' not in login_session or login_session['user_id'] != my_stuff.user_id:
        abort(404)
    elif request.method == 'POST':
        session.delete(my_stuff)
        session.commit()
        flash ('Stuff %s deleted' % my_stuff.name)
    else:
        return render_template('deleteStuff.html', stuff=my_stuff)

# JSON Endpoints
@app.route('/stuff/<int:stuff_id>/json/')
def showStuffJson(stuff_id):
    stuff = session.query(Stuff).filter_by(id=stuff_id).one_or_none()
    if stuff == None:
        abort(404)
    else:
        return jsonify(Stuff=stuff.serialize)

@app.route('/categories/<category_name>/json/')
def showCategoryJson(category_name):
    category = session.query(Category).filter_by(name=category_name).one_or_none()
    if category == None:
        abort(404)
    else:
        stuff = session.query(Stuff).filter_by(category_name=category_name).all()
        if stuff == None:
            return jsonify(Category=category.serialize)
        else:
            return jsonify(Category=category.serialize, Stuff_In_Category=[i.serialize for i in stuff])

@app.route('/json/')
def showEverythingJson():
    categories = session.query(Category).all()
    stuff = session.query(Stuff).all()
    if categories == None or stuff == None:
        abort(404)
    else:
        return jsonify(Categories=[i.serialize for i in categories], Stuff=[i.serialize for i in stuff])

# TODO Apply CSS to HTML pages

# TODO Apply PEP8 Styling

# TODO Comment code

# TODO Document in README

# Optional TODO Protect against CSRF
# https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet

# Optional TODO Images for stuff

if __name__ == '__main__':
    app.secret_key = '$$6R%$F2mIZxejYy$fv*JJXG3YNg9F2W'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
