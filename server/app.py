#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError


from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        # user_data ={key : value for key, value in request.get_json().items()}
        
        user_data = request.get_json()
        issues = {"errors" : []}

        # data validation before it hits the model / db side
        if user_data["username"] == "":
            issues["errors"].append("Username is missing")
        if user_data["password"] == "":
            issues["errors"].append("Password is missing")
        if user_data["password_confirmation"] == "":
            issues["errors"].append("Password confirmation is missing")
        if user_data["password"] != user_data["password_confirmation"]:
            issues["errors"].append("Passwords do not match.")    
        
        # username, image_url, bio = user_data
        _password_hash = user_data["password"]
        
        user = User(username=username, image_url=image_url, bio = bio, _password_hash = _password_hash)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError as e:
            errorInfo = e.orig.args
            print(errorInfo)
            {"errors":[errorInfo]}
        if len(issues["errors"]) > 0:
            status_code = 422
            print(issues)
            response = make_response(
                jsonify(issues),
                status_code
            )
            return response

        return {},201

class CheckSession(Resource):
    def get(self):
        pass
    pass

class Login(Resource):
    pass

class Logout(Resource):
    pass

class RecipeIndex(Resource):
    pass

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
