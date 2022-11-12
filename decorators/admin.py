import jwt

from functools import wraps
from flask import jsonify, request

from models.users import User


def admin_required(f):
    from app import app
    @wraps(f)
    def closure(*args, **kwargs):
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        if current_user.admin == False:
            return jsonify({'message' : 'You are not an admin'})
            
        return f(*args, **kwargs)
    return closure
