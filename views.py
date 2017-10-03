# -*- coding: utf-8 -*-
from flask import Flask, render_template, url_for, send_from_directory
from flask import request, redirect, flash, jsonify

# imports para base de dados
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import func
from models import Base, Marca, ItemMarca, User

# IMPORTS for the authentication step
from flask import session as login_session
import random, string

# MORE IMPORTS for step5 GConnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

#encoding stuff
import sys
import codecs
sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

#upload stuff
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static'
ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg', 'gif'])

#teste
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Marcas Application"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

engine = create_engine('postgresql:///catalogoestilo')
Base.metadata.bind = engine

DBSession = sessionmaker(bind = engine)
session = DBSession()


'''
	Rota para logins/autenticacao
'''

# ROTA LOGIN / -> Create anti-forgery state token (Nao sei nem como nem pq)
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
        for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# ROTA FACEBOOK CONNECT

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
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

    flash("Now logged in as %s" % login_session['username'])
    print 'Done!'
    return output

# ROTA FACEBOOK DISCONNECT
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out from facebook"



#####

# ROTA GOOGLE CONNECT
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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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
    login_session['provider'] = 'google'

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Checando para ver se o user existe, caso contrario ja criamos um novo user na base de dados
    user_id = getUserID(login_session['email'])
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

# ROTA Google Disconnect
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s' % access_token
    print 'User name is: '
    print login_session['username']
    print login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        #del login_session['access_token']
        #del login_session['gplus_id']
        #del login_session['username']
        #del login_session['email']
        #del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected from google.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# ROTA DISCONNECT for other providers
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('marcasGuide'))
    else:
        flash("You were not logged in")
        return redirect(url_for('marcasGuide'))


# route to Search page
@app.route('/search')
def search():
    nameQuery = request.args.get('query')
    marcas = session.query(Marca).filter(Marca.name.ilike('%'+nameQuery+'%'))
    if marcas.first() == None:
        marcas = session.query(Marca).filter(Marca.description.ilike('%'+nameQuery+'%'))
        visita = getUserID(login_session['email'])
        if 'username' not in login_session:
            return render_template('publicmarcas.html', marcas=marcas)    
        return render_template('publicmarcas.html', marcas=marcas,
        username='username', login_session=login_session, visita=visita)
    if 'username' not in login_session:
        return render_template('publicmarcas.html', marcas=marcas)    
    visita = getUserID(login_session['email'])
    return render_template('publicmarcas.html', marcas=marcas,
        username='username', login_session=login_session, visita=visita)

'''

	Pagina das Lojas

'''

# Principal pagina com TODAS as Lojas
@app.route('/')
@app.route('/marcas/')
def marcasGuide():
    marcas = session.query(Marca).order_by(func.random()).all()
    marca_test = session.query(Marca).first()
    if 'username' not in login_session:
        return render_template('publicmarcas.html', marcas=marcas,
            marca_test=marca_test)
    else:
        visita = getUserID(login_session['email'])
        check = ownStoreCheck(login_session)
        # see if there is a marca in the list
    return render_template('publicmarcas.html', marcas=marcas,
        username='username', login_session=login_session,
        marca_test=marca_test, visita=visita, check=check)


'''
    ROTAS PARA AS MARCAS
'''

# Deletar uma marca
@app.route('/marcas/<int:marca_id>/delete/', methods=['GET', 'POST'])
def deleteMarca(marca_id):
    #deletar a marca e os items pq se deleta só as marcas os items ficam la veiculados ao id da marca
    deleteMarca = session.query(Marca).filter_by(id=marca_id).one()
    deleteItens = session.query(ItemMarca).filter_by(marca_id=marca_id)
    if 'username' not in login_session:
        return redirect('/login')
    elif getUserID(login_session['email'])!=deleteMarca.user_id:
        return "<script> function myFunction()\
        {alert('You are not authorized to delete this marca')\
        ;}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        x = str(deleteMarca.id)
        nomeMarca = deleteMarca.name.replace(" ", "")
        marcapic = "static/"+nomeMarca+x+'.jpg'
        check = os.path.isfile(marcapic)
        if check == True:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], deleteMarca.picture))
        session.delete(deleteMarca)
        for deleteItem in deleteItens:
            y = str(deleteItem.id)
            nomeItem = deleteItem.name.replace(" ", "")
            itemPic = "static/"+nomeMarca+x+nomeItem+y+'.jpg'
            check = os.path.isfile(itemPic)
            if check == True:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], deleteItem.picture))
        deleteItens.delete()
        session.commit()
        flash(deleteMarca.name+" was deleted!")
        return redirect(url_for('myStoreList'))
    else:
        return render_template('delete_marca.html', marca_id=marca_id,
        deleteMarca=deleteMarca) # nao entendi pq esse ultimo argumento

# Editar o nome de marca
@app.route('/marcas/<int:marca_id>/edit/', methods=
    ['GET', 'POST'])
def editMarca(marca_id):
    editedMarca = session.query(Marca).filter_by(id=marca_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedMarca.name = request.form['name']
        if request.form['description']:
            editedMarca.description = request.form['description']    
        session.add(editedMarca)
        session.commit()
        if 'file' not in request.files:
            flash("The marca was edited!1")
            return redirect(url_for('marcasGuide'))
        file = request.files['file']
        if file.filename == '':
            flash('The marca was edited!2')
            return redirect(url_for('marcasGuide'))
        if file and allowed_file(file.filename):
            x = str(editedMarca.id)
            nomeMarca = editedMarca.name.replace(" ", "")
            marcapic = "static/"+nomeMarca+x+'.jpg'
            check = os.path.isfile(marcapic)
            if check == True:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], editedMarca.picture))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], editedMarca.picture))
            # x = str(x)
            nomeMarca = editedMarca.name.replace(" ", "")
            editedMarca.picture = nomeMarca+x+'.jpg'
            session.add(editedMarca)
            session.commit()
            flash('The marca was edited!3')
            return redirect(url_for('marcasGuide'))
        return redirect(url_for('myStoreList'))
    else:
        return render_template('edit_marca.html',marca_id=marca_id,
            marca=editedMarca)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Nova marca criar nao posso permitir adicionar sem foto
@app.route('/marcas/new/', methods=['GET', 'POST'])
def newMarca():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newMarc = Marca(name = request.form['name'],
            user_id=login_session['user_id'], description = request.form['description'])
        if 'file' not in request.files:
            flash('No picture added')
            return redirect(url_for('marcasGuide'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected picture')
            return redirect(url_for('marcasGuide'))
        session.add(newMarc)
        session.commit()
        x = str(newMarc.id)
        # x = str(x)
        nomeMarca = newMarc.name.replace(" ", "")
        newMarc.picture = nomeMarca+x+'.jpg'
        session.add(newMarc)
        session.commit()
        flash(newMarc.name +" was added!")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], newMarc.picture))
            pic = newMarc.picture
            return redirect(url_for('marcasGuide', pic=pic))
        return redirect(url_for('myStoreList'))
    else:
        return render_template('add_marca.html')

    
'''
    Pagina indivual das marcas
'''

# Marcas, pagina individual de cada um
@app.route('/marcas/<int:marca_id>/')
def marcaVitrine(marca_id): # restaurantMenu
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    creator = getUserInfo(marca.user_id)
    items = session.query(ItemMarca).filter_by(
        marca_id = marca_id)
    marcaItem = session.query(ItemMarca).filter_by(
        marca_id=marca_id).first()
    '''
    vest = session.query(ItemMarca).filter_by(marca_id=marca_id,
        peca="Vestido").first()
    cal = session.query(ItemMarca).filter_by(marca_id=marca_id,
        peca="Calca").first()
    blu = session.query(ItemMarca).filter_by(marca_id=marca_id,
        peca="Blusa").first()
    shor = session.query(ItemMarca).filter_by(marca_id=marca_id,
        peca="Short").first()
    '''
    if 'username' not in login_session:
        return render_template('publicvitrine.html', marca=marca,
            items=items, marcaItem=marcaItem, username='username',
            login_session=login_session, creator=creator)
    else:
        visita = getUserID(login_session['email'])
        check = ownStoreCheck(login_session)
        if visita==creator.id:
            return render_template('publicvitrine.html', marca=marca,
                items=items, marcaItem=marcaItem, username='username',
                login_session=login_session, creator=creator, visita=visita,
                check=check) #talvez 
        else:
            return render_template('publicvitrine.html', marca=marca,
                items=items, marcaItem=marcaItem, username='username',
                login_session=login_session, creator=creator, visita=visita,
                check=check)

'''
    ROTA PARA OS ITENS
'''

# Add um new item
@app.route('/marcas/<int:marca_id>/new/', methods=['GET', 'POST'])
def newItens(marca_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    elif getUserID(login_session['email'])!=marca.user_id:
        return "<script> function myFunction() {alert('You are not authorized to create itens \
in this marca. Create Items on your own \
marca.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = ItemMarca(name = request.form['name'], peca = request.form['peca'],
            description = request.form['description'], price = request.form['price'],
            marca_id=marca_id, user_id=login_session['user_id'])
        if 'file' not in request.files:
            flash('You have to add a picture1')
            return redirect(url_for('marcaVitrine', marca_id=marca_id))
        file = request.files['file']
        if file.filename == '':
            flash('You have to add a picture2')
            return redirect(url_for('marcaVitrine', marca_id=marca_id))
        if not allowed_file(file.filename):
            flash('This type of file is not allowed!')
            return redirect(url_for('marcaVitrine', marca_id=marca_id))
        if file and allowed_file(file.filename):
            newItem.quantityP = 0
            newItem.quantityM = 0
            newItem.quantityG = 0
            session.add(newItem)
            session.commit()
            x = str(marca.id)
            y = str(newItem.id)
            nomeMarca = marca.name.replace(" ", "")
            nomeItem = newItem.name.replace(" ", "")
            newItem.picture = nomeMarca+x+nomeItem+y+'.jpg'
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], newItem.picture))
            session.add(newItem)
            session.commit()
            pic = newItem.picture
            flash("New item added!")
        return redirect(url_for('myStore', marca_id=marca_id))
    else:
        return render_template('add_item.html', marca_id=
            marca_id)

# Editar um item
@app.route('/marcas/<int:marca_id>/<int:item_id>/edit/', methods=
    ['GET', 'POST'])
def editItem(marca_id, item_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    editedItem = session.query(ItemMarca).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    elif getUserID(login_session['email'])!=marca.user_id:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['peca']:
            editedItem.peca = request.form['peca']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        flash("Item was edited!")
        print os.path.join(app.config['UPLOAD_FOLDER'], editedItem.picture)
        if 'file' not in request.files:
            flash("Item was edited!1")
            return redirect(url_for('myStore', marca_id=marca_id))
        file = request.files['file']
        if file.filename == '':
            flash("Item was edited!2")
            return redirect(url_for('myStore', marca_id=marca_id))
        if file and allowed_file(file.filename):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], editedItem.picture))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], editedItem.picture))
            flash('The marca was edited!3')
            return redirect(url_for('myStore', marca_id=marca_id))
        return redirect(url_for('myStore', marca_id=marca_id))
    else:
        return render_template('edit_item.html', marca_id=marca_id,
            item_id=item_id, i=editedItem) # Este 'i' eh pq na pagina de editar ele vai reconhcer o editedItem

# Deletar um item
@app.route('/marcas/<int:marca_id>/<int:item_id>/delete/', methods=
    ['GET', 'POST'])
def deleteItem(marca_id, item_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    deletItem = session.query(ItemMarca).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    elif getUserID(login_session['email'])!= marca.user_id:
        return redirect('/login')
    if request.method == 'POST':
        x = str(marca.id)
        y = str(deletItem.id)
        nomeMarca = marca.name.replace(" ", "")
        nomeItem = deletItem.name.replace(" ", "")
        itemPic = "static/"+nomeMarca+x+nomeItem+y+'.jpg'
        check = os.path.isfile(itemPic)
        if check == True:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], deletItem.picture))
        session.delete(deletItem)
        session.commit()
        flash("Item was deleted!")
        return redirect(url_for('myStore', marca_id=marca_id))
    else:
        return render_template('delete_item.html', marca_id=marca_id,
            item_id=item_id, i=deletItem) # Preciso do i aqui?

# Manage Inventory route
@app.route('/marcas/<int:marca_id>/<int:item_id>/inventory/', methods=
    ['GET', 'POST'])
def mngInventory(marca_id, item_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    item = session.query(ItemMarca).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    elif getUserID(login_session['email'])!=marca.user_id:
        return redirect('/login') # tvz tenho que redirecionar para outra pagina
    if request.method == 'POST':
        if request.form['size'] == "P":
            p = item.quantityP
            q = request.form['quantity']
            print p
            print q
            print type(p)
            print type(q)
            item.quantityP = int(p) + int(q)
        if request.form['size'] == "M":
            p = item.quantityM
            q = request.form['quantity']
            item.quantityM = int(p) + int(q)
        if request.form['size'] == "G":
            p = item.quantityG
            q = request.form['quantity']
            item.quantityG = int(p) + int(q)
        session.add(item)
        session.commit()
        flash("Were added "+str(q)+" itens of the size " + request.form['size'])
        return redirect(url_for('myStore', marca_id=marca_id))
    else:
        check = ownStoreCheck(login_session)
        return render_template('inventory.html', marca_id=marca_id,
            item_id=item_id, i=item, check=check)



# Rota para itens individuais
@app.route('/marcas/<int:marca_id>/<int:item_id>/item/', methods=
    ['GET', 'POST'])
def buyItem(marca_id, item_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    item = session.query(ItemMarca).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return render_template('item.html', marca_id=marca_id,
            item_id=item_id, i=item)
    return render_template('item.html', marca_id=marca_id,
            item_id=item_id, i=item)

# Route to My Store List
@app.route('/mystore/')
def myStoreList():
    if 'username' not in login_session:
        return redirect('/login')
    visita = getUserID(login_session['email'])
    check = ownStoreCheck(login_session)
    marcas = session.query(Marca).filter_by(user_id=visita).all()
    if check == True:
        return render_template('mystorelist.html',
            check=check, login_session=login_session, marcas=marcas)
    return redirect('/')

# Route to My Store
@app.route('/mystore/<int:marca_id>/')
def myStore(marca_id):
    if 'username' not in login_session:
        return redirect('/login')
    visita = getUserID(login_session['email'])
    check = ownStoreCheck(login_session)
    itens = session.query(ItemMarca).filter_by(marca_id=marca_id).all()
    marca = session.query(Marca).filter_by(id=marca_id).first()
    if check == True:
        return render_template('mystore.html', itens=itens,
            check=check, login_session=login_session, marca=marca)
    return redirect('/')

# If someone add an item to the cart it is reduced from the inventory
@app.route('/marcas/<int:marca_id>/<int:item_id>/itembuy/', methods=
    ['GET','POST'])
def itemBought(marca_id,item_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    item = session.query(ItemMarca).filter_by(id=item_id).one()
    if request.method == 'POST':
        itemSize = request.form['os0']
        if itemSize == "P":
            item.quantityP = item.quantityP -1
        if itemSize == "M":
            item.quantityM = item.quantityM -1
        if itemSize == "G":
            item.quantityG = item.quantityG -1
        return redirect(url_for('marcaVitrine', marca_id=marca_id))
    return render_template('404.html')

# Error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

'''
    APIs
'''

# Making an API Endpoint (GET Requests) - Marcas
@app.route('/marcas/<int:marca_id>/vitrine/JSON')
def marcaJSON(marca_id):
    marca = session.query(Marca).filter_by(
        id = marca_id).one()
    items = session.query(ItemMarca).filter_by(marca_id=
        marca_id).all()
    return jsonify(ItemMarca=[i.serialize for i in items])

# Making an API Endpoint (GET Requests) - Itens especificos
@app.route('/marcas/<int:marca_id>/vitrine/<int:item_id>/JSON')
def ItemMarcaJSON(marca_id, item_id):
    MarcaItem = session.query(ItemMarca).filter_by(id=
        item_id).one()
    return jsonify(ItemMarca=[MarcaItem.serialize])

@app.route('/marcas/JSON')
def marcasGeralJSON():
    marcas = session.query(Marca).all()
    return jsonify(ListaMarcas=[marca.serialize for marca in marcas])

'''
	Login stuff
'''


def getUserID(emails):
    try:
        user = session.query(User).filter_by(email=emails).one()
        return user.id
    except:
    	return None

def getUserInfo(user_ids):
	user = session.query(User).filter_by(id = user_ids).one()
	return user

def createUser(login_session):
    newUser = User(name = login_session['username'],
        email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email= login_session['email']).one()
    return user.id

# check if the logged in user owns a store in the website
def ownStoreCheck(login_session):
    visita = getUserID(login_session['email'])
    marcas = session.query(Marca).all()
    count = 0
    for marca in marcas:
        if visita == marca.user_id:
            count += 1
    if count > 0:
        return True
    else:
        return False

if __name__ == '__main__':
    app.secret_key = "super_secret_key" #why this super secret key??? e como fazer essa super key que eu no estoy ligado?
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)

