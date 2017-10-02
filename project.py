from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
import os

app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

from flask import session as login_session
import random
import string

# import for auth flow: GConnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# using facebook-sdk for python
import facebook

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read()
)['web']['client_id']
APPLICATION_NAME = 'Restaurant Menu Application'

# Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    # create a state token to prevent request forgery
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, CLIENT_ID=CLIENT_ID)


# User API
def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template('publicrestaurants.html', restaurants=restaurants)
    else:
        return render_template('restaurants.html', restaurants=restaurants)


# Create a new restaurant


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newRestaurant = Restaurant(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant=editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if restaurantToDelete.user_id != login_session['user_id']:
        return """
            <script>
                function myFunction() {
                    alert('You are not authorized to delete this restaurant.')
                }
            </script>
            <body onload='myFunction()'>
        """
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html', restaurant=restaurantToDelete)


# Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if 'user_id' in login_session and creator.id == login_session['user_id']:
        return render_template('menu.html', items=items, restaurant=restaurant, creator=creator)
    else:
        return render_template('publicmenu.html', items=items, restaurant=restaurant, creator=creator)



# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form['description'],
                           price=request.form['price'], course=request.form['course'], restaurant_id=restaurant_id, user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id,
                               item=editedItem)  
                               

# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)


# Connect with Google account
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # 1. Validate state token
    if request.args.get('state') != login_session['state']:
        return resp_json('Invalid state parameter.', 401)

    # 2. Obtain authorization code
    code = request.data
    print("code", code)
    print("type of code: ", type(code))

    # 3. Upgrade the authorization code into a credentials object
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code=code)
    except FlowExchangeError:
        return resp_json('Failed to upgrade the authorization code.', 401)

        # 4. Check that the access token is valid
        # If error, abort
    access_token = credentials.access_token
    url = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s" % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        return resp_json(result.get('error'), 500)

    # 5. Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return resp_json("Token's user ID doesn't match given user ID.", 401)

    # 6. Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        return resp_json("Token's client ID does not match app's client ID.", 401)

    # 7. Check if the user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        return resp_json("Current user is already connected.", 200)

    # 8. Store the access token in the session for later use
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # 9. Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {
        'access_token': credentials.access_token,
        'alt': 'json'
    }
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print(data)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # 10. Check if user exists, if not then create new user
    user_id = getUserId(login_session['email'])
    if user_id is None:
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


# Facebook login
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        return resp_json('Invalid state parameters.', 401)

    access_token = request.data.decode('utf-8')

    # exchange client token for long-lived server-side token
    fb_client_secrets = json.loads(open('fb_client_secrets.json', 'r').read())['web']
    app_id = fb_client_secrets['app_id']
    app_secret = fb_client_secrets['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    exchange_result = h.request(url, 'GET')
    result = exchange_result[1]

    # Use token to get user info from API
    token = json.loads(result.decode('utf-8'))['access_token']
    
    # graph = facebook.GraphAPI(access_token=token, version="2.7")
    # args = {
    #     'fields': 'id,name,email'
    # }
    # data = graph.get_object('me', **args)

    userinfo_url = "https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email" % token
    info_result = h.request(userinfo_url, 'GET')[1]
    data = json.loads(info_result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # store token
    login_session['access_token'] = token

    # get user picture
    h = httplib2.Http()
    picture_result = h.request("https://graph.facebook.com/v2.2/me/picture?access_token=%s&redirect=false&height=200&width=200" % token, 'GET')[1]
    picture_data = json.loads(picture_result)
    # print(picture_data)
    login_session['picture'] = picture_data["data"]["url"]

    # Check if user exists
    user_id = getUserId(login_session['email'])
    if not user_id:
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


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        elif login_session['provider'] == 'facebook':
            fbdisconnect()

        flash('You have successfully been logged out.')
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in to begin with!")
        return redirect(url_for('showRestaurants'))


# Step 6: disconnect -> revoke current user's token and reset login_session
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        print("Access Token is None")
        return resp_json('Current user not connected', 401)

    print("In gdisconnect access token is ", access_token)
    print("User name is: ", login_session['username'])

    # execute HTTP GET request to revoke current token
    url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % login_session["access_token"]
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print("Result: ", result)

    if result['status'] == '200':
        del login_session['provider']
        del login_session['user_id']
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return resp_json('Successfully disconnected!', 200)
    else:
        return resp_json('Failed to revoke token for given user.', 400)


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = "https://graph.facebook.com/%s/permissions?access_token=%s" % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')
    result_status = json.loads(result[1])

    if result_status['success'] == True:
        del login_session['provider']
        del login_session['user_id']
        del login_session['access_token']
        del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return resp_json('Successfully disconnected!', 200)
    else:
        return resp_json('Failed to revoke token for given user.', 400)


def resp_json(mess, code):
    response = make_response(json.dumps(mess), code)
    response.headers['Content-Type'] = 'application/json'
    return response


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
