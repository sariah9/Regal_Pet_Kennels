"""
Sariah Bunnell
CS493: Cloud Development
Assignment 9: Final Project
Sources: Assignment 4, 5, 7
"""

import uuid

from google.cloud import datastore
from flask import request, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())
client = datastore.Client()

PETS = "pets"
KENNELS = "kennels"
USERS = "users"

CLIENT_ID = 'fxJLnln1iOM2eGeJgEjvYxreXxgKFBQu'
CLIENT_SECRET = 'vf633fL1BGqgxJAhZldYvE-31H3xu1aDRL1v9bVa6HGRqB-xLjSgT8oK0cP-TjFF'
DOMAIN = 'bunnells.us.auth0.com'
API_AUDIENCE = 'https://bunnells.us.auth0.com/api/v2/'
CALLBACK_URL = 'https://bunnells493hw.wl.r.appspot.com/callback'
ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_check(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/ui_login')
        return f(*args, **kwargs)

    return decorated


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    jwt_header_auth = request.headers.get('Authorization')
    if jwt_header_auth is None:
        return None
    auth_header = request.headers['Authorization'].split()
    token = auth_header[1]

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return None
    if unverified_header["alg"] == "HS256":
        return None
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                # changed from suggested API_AUDIENCE
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTClaimsError:
            return None
        return payload
    else:
        return None


@app.route('/')
def index():
    return render_template('welcome.html')


@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    jwt_token = auth0.authorize_access_token()['id_token']
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt'] = jwt_token
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }

    # add new user to users
    query = client.query(kind=USERS)
    results = list(query.fetch())
    add_user = True
    for e in results:
        if e["id"] == userinfo['sub']:
            add_user = False
    if add_user:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"name": userinfo['name'], "id": userinfo['sub']})
        client.put(new_user)

    return redirect('/dashboard')


@app.route('/ui_login')
def ui_login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL, audience=API_AUDIENCE)


@app.route('/dashboard')
@requires_check
def dashboard():
    return render_template('userdata.html', userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4),
                           jwt_token=session['jwt'])


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('index', _external=True), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


"""
Users Entities Routing - read users list
also see /ui_login for create user functionality
UNPROTECTED
"""


@app.route('/users', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def list_users():
    if request.method == 'GET':
        if 'application/json' in request.accept_mimetypes:
            query = client.query(kind=USERS)
            results = list(query.fetch())
            return json.dumps(results), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "The response content type is not supported by this API"}), \
                   406, {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


"""
Pets Entities Routing
create a pet, read a pet, read pets, update a pet with PUT and PATCH, delete a pet
PROTECTED by JWT headers
"""


@app.route('/pets', methods=['POST', 'GET', 'PUT', 'PATCH', 'DELETE'])
def get_post_pets():
    if request.method == 'POST':
        # add a pet
        content = request.get_json()
        payload = verify_jwt(request)
        if payload:
            if 'application/json' in request.accept_mimetypes:
                new_pet = datastore.entity.Entity(key=client.key(PETS))
                new_pet.update({"name": content["name"], "type": content["type"], "weight": content["weight"],
                                "owner": payload["sub"], "kennel": None})
                client.put(new_pet)
                new_pet["id"] = new_pet.key.id
                new_pet["self"] = request.base_url + "/" + str(new_pet.key.id)
                return json.dumps(new_pet), 201, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The response content type is not supported by this API"}), \
                       406, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    elif request.method == 'GET':
        # view all pets
        payload = verify_jwt(request)
        if payload:
            if 'application/json' in request.accept_mimetypes:
                query = client.query(kind=PETS)
                query_results = list(query.fetch())
                count = len(query_results)
                q_limit = int(request.args.get('limit', '5'))
                q_offset = int(request.args.get('offset', '0'))
                l_iterator = query.fetch(limit=q_limit, offset=q_offset)
                pages = l_iterator.pages
                results = list(next(pages))
                if l_iterator.next_page_token:
                    next_offset = q_offset + q_limit
                    next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
                else:
                    next_url = None
                owned_pets = []
                for e in results:
                    if e["owner"] == payload["sub"]:
                        e["id"] = e.key.id
                        e["self"] = request.base_url + "/" + str(e.key.id)
                        owned_pets.append(e)
                output = {"pets": owned_pets, "total": count}
                if next_url:
                    output["next"] = next_url
                return json.dumps(output), 200, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The response content type is not supported by this API"}), \
                       406, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


@app.route('/pets/<pet_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE', 'POST'])
def get_edit_delete_pets(pet_id):
    if request.method == 'GET':
        # view a pet
        payload = verify_jwt(request)
        pet_key = client.key(PETS, int(pet_id))
        pet = client.get(key=pet_key)
        if payload and pet["owner"] == payload["sub"]:
            if 'application/json' in request.accept_mimetypes:
                pet["id"] = pet.key.id
                pet["self"] = request.base_url
                return json.dumps(pet), 200, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The response content type is not supported by this API"}), \
                       406, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    elif request.method == 'PUT':
        # edit a pet
        content = request.get_json()
        payload = verify_jwt(request)
        pet_key = client.key(PETS, int(pet_id))
        pet = client.get(key=pet_key)
        if payload and pet["owner"] == payload["sub"]:
            if 'application/json' in request.accept_mimetypes:
                pet.update({"name": content["name"], "type": content["type"], "weight": content["weight"],
                            "owner": pet["owner"], "kennel": pet["kennel"]})
                client.put(pet)
                pet["id"] = pet.key.id
                pet["self"] = request.base_url
                return json.dumps(pet), 200, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The response content type is not supported by this API"}), \
                       406, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    elif request.method == 'PATCH':
        # edit partial pet
        content = request.get_json()
        count = len(content.keys())
        payload = verify_jwt(request)
        pet_key = client.key(PETS, int(pet_id))
        pet = client.get(key=pet_key)
        proceed = False
        if payload and pet["owner"] == payload["sub"]:
            if 'application/json' in request.accept_mimetypes:
                if count == 1:
                    if "name" in content:
                        pet.update({"name": content["name"], "type": pet["type"], "weight": pet["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    elif "type" in content:
                        pet.update({"name": pet["name"], "type": content["type"], "weight": pet["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    elif "weight" in content:
                        pet.update({"name": pet["name"], "type": pet["type"], "weight": content["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    else:
                        proceed = False
                if count == 2:
                    if "name" in content and "type" in content:
                        pet.update({"name": content["name"], "type": content["type"], "weight": pet["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    elif "type" in content and "weight" in content:
                        pet.update({"name": pet["name"], "type": content["type"], "weight": content["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    elif "name" in content and "weight" in content:
                        pet.update({"name": content["name"], "type": pet["type"], "weight": content["weight"],
                                    "owner": pet["owner"], "kennel": pet["kennel"]})
                        proceed = True
                    else:
                        proceed = False
                if proceed:
                    client.put(pet)
                    pet["id"] = pet.key.id
                    pet["self"] = request.base_url
                    return json.dumps(pet), 200, {'ContentType': 'application/json'}
                else:
                    return json.dumps({"Error": "Request attributes are missing or incorrect"}), \
                           403, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The response content type is not supported by this API"}), \
                       406, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    elif request.method == 'DELETE':
        # delete a pet
        payload = verify_jwt(request)
        key = client.key(PETS, int(pet_id))
        pet = client.get(key=key)
        if payload and pet["owner"] == payload["sub"]:
            if pet["kennel"] is not None:
                k_key = client.key(KENNELS, int(pet["kennel"]))
                kennel = client.get(key=k_key)
                if "pets" in kennel.keys():
                    for e in kennel["pets"]:
                        if e == pet_id:
                            kennel["pets"].remove(e)
                            client.put(kennel)
            client.delete(key)
            return '', 204
        else:
            return json.dumps({"Error": "Incorrect authentication credentials"}), \
                   401, {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


"""
Kennels Entities Routing
create a kennel, read a kennel, read kennels, update a kennel with PUT and PATCH, delete a kennel
pet added to kennel, pet removed from kennel
PROTECTED by JWT headers
"""


@app.route('/kennels', methods=['POST', 'GET', 'PUT', 'PATCH', 'DELETE'])
def get_post_kennels():
    if request.method == 'POST':
        content = request.get_json()
        # add a kennel
        if 'application/json' in request.accept_mimetypes:
            if "size" in content and "inside" in content and "public" in content:
                new_kennel = datastore.entity.Entity(key=client.key(KENNELS))
                new_kennel.update({"size": content["size"], "inside": content["inside"], "public": content["public"]})
                client.put(new_kennel)
                new_kennel["id"] = new_kennel.key.id
                new_kennel["self"] = request.base_url + "/" + str(new_kennel.key.id)
                return json.dumps(new_kennel), 201, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "The request object is missing at least one of the required attributes"}), \
                       400, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "The response content type is not supported by this API"}), \
                   406, {'ContentType': 'application/json'}
    elif request.method == 'GET':
        # view all boats
        if 'application/json' in request.accept_mimetypes:
            query = client.query(kind=KENNELS)
            query_results = list(query.fetch())
            count = len(query_results)
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            b_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = b_iterator.pages
            results = list(next(pages))
            if b_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + "/" + str(e.key.id)
            output = {"kennels": results, "total": count}
            if next_url:
                output["next"] = next_url
            return json.dumps(output), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "The response content type is not supported by this API"}), 406, \
                   {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


@app.route('/kennels/<kennel_id>', methods=['GET', 'DELETE', 'POST', 'PUT', 'PATCH'])
def get_edit_delete_kennels(kennel_id):
    if request.method == 'GET':
        # view a kennel
        if 'application/json' in request.accept_mimetypes:
            kennel_key = client.key(KENNELS, int(kennel_id))
            kennel = client.get(key=kennel_key)
            kennel["id"] = kennel.key.id
            kennel["self"] = request.base_url
            return json.dumps(kennel), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "The response content type is not supported by this API"}), 406, \
                   {'ContentType': 'application/json'}
    elif request.method == 'PUT':
        # edit a kennel
        content = request.get_json()
        kennel_key = client.key(KENNELS, int(kennel_id))
        kennel = client.get(key=kennel_key)
        if kennel:
            if 'pets' in kennel.keys():
                kennel.update({"size": content["size"], "inside": content["inside"], "public": content["public"],
                               "pets": kennel["pets"]})
            else:
                kennel.update({"size": content["size"], "inside": content["inside"], "public": content["public"]})
            client.put(kennel)
            kennel["id"] = kennel.key.id
            kennel["self"] = request.base_url
            return json.dumps(kennel), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "No kennel with this kennel_id exists"}), \
                   404, {'ContentType': 'application/json'}
    elif request.method == 'PATCH':
        # edit partial pet
        content = request.get_json()
        count = len(content.keys())
        kennel_key = client.key(KENNELS, int(kennel_id))
        kennel = client.get(key=kennel_key)
        proceed = False
        if kennel:
            if count == 1:
                if "size" in content:
                    kennel.update({"size": content["size"], "inside": kennel["inside"], "public": kennel["public"]})
                    proceed = True
                elif "inside" in content:
                    kennel.update({"size": kennel["size"], "inside": content["inside"], "public": kennel["public"]})
                    proceed = True
                elif "public" in content:
                    kennel.update({"size": kennel["size"], "inside": kennel["inside"], "public": content["public"]})
                    proceed = True
                else:
                    proceed = False
            if count == 2:
                if "size" in content and "inside" in content:
                    kennel.update({"size": content["size"], "inside": content["inside"], "public": kennel["public"]})
                    proceed = True
                elif "inside" in content and "public" in content:
                    kennel.update({"size": kennel["size"], "inside": content["inside"], "public": content["public"]})
                    proceed = True
                elif "size" in content and "public" in content:
                    kennel.update({"size": content["size"], "inside": kennel["inside"], "public": content["public"]})
                    proceed = True
                else:
                    proceed = False
            if "pets" in kennel.keys():
                kennel.update({"pets": kennel["pets"]})
            if proceed:
                client.put(kennel)
                kennel["id"] = kennel.key.id
                kennel["self"] = request.base_url
                return json.dumps(kennel), 200, {'ContentType': 'application/json'}
            else:
                return json.dumps({"Error": "Request attributes are missing or incorrect"}), \
                       403, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "No kennel with this kennel_id exists"}), \
                   404, {'ContentType': 'application/json'}
    elif request.method == 'DELETE':
        # delete a kennel
        kennel_key = client.key(KENNELS, int(kennel_id))
        kennel = client.get(key=kennel_key)
        if kennel:
            if "pets" in kennel.keys():
                for e in kennel["pets"]:
                    p_key = client.key(PETS, int(e))
                    pet = client.get(key=p_key)
                    pet.update({"name": pet["name"], "type": pet["type"], "weight": pet["weight"],
                                "owner": pet["owner"], "kennel": None})
                    client.put(pet)
                    kennel["pets"].remove(e)
            client.delete(kennel_key)
            return '', 204
        else:
            return json.dumps({"Error": "No kennel with this kennel_id exists"}), \
                   404, {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


@app.route('/kennels/<kennel_id>/pets/<pet_id>', methods=['PUT', 'DELETE'])
def add_remove_pets(kennel_id, pet_id):
    if request.method == 'PUT':
        # pet added to kennel
        pet_key = client.key(PETS, int(pet_id))
        kennel_key = client.key(KENNELS, int(kennel_id))
        pet = client.get(key=pet_key)
        kennel = client.get(key=kennel_key)
        if pet and kennel:
            if pet["kennel"] is None:
                pet.update({"name": pet["name"], "type": pet["type"], "weight": pet["weight"], "owner": pet["owner"],
                            "kennel": kennel.key.id})
                client.put(pet)
                if "pets" in kennel.keys():
                    kennel["pets"].append(pet.id)
                else:
                    kennel["pets"] = [pet.id]
                client.put(kennel)
                return '', 204
            else:
                return json.dumps({"Error": "This pet is already assigned to another kennel"}), \
                       403, {'ContentType': 'application/json'}
        else:
            return json.dumps({"Error": "No kennel with this kennel_id exists, and/or no pet with this pet_id exists"}), \
                   404, {'ContentType': 'application/json'}
    elif request.method == 'DELETE':
        # pet removed from kennel
        pet_key = client.key(PETS, int(pet_id))
        kennel_key = client.key(KENNELS, int(kennel_id))
        pet = client.get(key=pet_key)
        kennel = client.get(key=kennel_key)
        if pet and pet["kennel"] is not None and pet["kennel"] == kennel.key.id:
            for g in kennel["pets"]:
                if g == pet.key.id:
                    kennel["pets"].remove(g)
                    pet.update({"name": pet["name"], "type": pet["type"], "weight": pet["weight"],
                                "owner": pet["owner"], "kennel": None})
                    client.put(kennel)
                    client.put(pet)
                    return '', 204
        return json.dumps({"Error": "This pet is not in this kennel"}), 404, {'ContentType': 'application/json'}
    else:
        return json.dumps({"Error": "The request verb is not supported on this URL"}), \
               405, {'ContentType': 'application/json'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
