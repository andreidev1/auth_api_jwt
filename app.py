
import datetime
import uuid
import jwt
from functools import wraps

from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_restx import Api, Resource, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


from models.users import User
from decorators.admin import admin_required
from decorators.token import token_required

app = Flask(__name__)

app.config.from_object('config.Config')


db = SQLAlchemy(app)

migrate = Migrate(app, db) 



api = Api(app)




userFields = {
    'admin' : fields.String,
    'id' : fields.Integer,
    'public_id' : fields.String,
    'name' : fields.String,
    'password' : fields.String
}


tokenField = {
    'token' : fields.String
}


class Users(Resource):
    @marshal_with(userFields)
    @token_required
    @admin_required
    def get(self):

        users = User.query.all()

        return users    


    @token_required
    @admin_required
    def post(self):
        data = request.json

        hashed_password = generate_password_hash(data['password'], method='sha256')

        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)

        db.session.add(new_user)
        db.session.commit()

        
        return jsonify({'message' : 'New user created!'})

    @token_required
    @admin_required
    def put(self):

        data = request.json

        
        promote_user = User.query.filter_by(public_id=data['public_id']).first()

        
        promote_user.admin = True

        
        db.session.commit()

        return {'message' : 'User : ' + promote_user.name + ' promoted'}, 200
        

class GetOneUser(Resource):

    @marshal_with(userFields)
    @token_required
    @admin_required
    def get(self, id):

        user = User.query.filter_by(id=id).first()

        return user


class LoginUser(Resource):

    @marshal_with(tokenField)
    def post(self):

        auth = request.authorization

        user = User.query.filter_by(name=auth.username).first()

        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            decoded_token = token.decode('UTF-8')
            
            

        return {'token' : decoded_token}



api.add_resource(Users, '/users')
api.add_resource(GetOneUser, '/user/<int:id>')
api.add_resource(LoginUser, '/login')

