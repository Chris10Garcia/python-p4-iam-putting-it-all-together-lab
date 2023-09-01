#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from marshmallow_sqlalchemy.fields import Nested
from werkzeug import exceptions
from sqlalchemy.exc import IntegrityError

from config import app, db, api, ma
from models import User, Recipe

class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True
    id = ma.auto_field()
    username = ma.auto_field()
    image_url = ma.auto_field()
    bio = ma.auto_field()    

class RecipeSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Recipe
        load_instance = True
    user = Nested(UserSchema)

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipe_many_schema = RecipeSchema(many=True)


class Signup(Resource):
    def post(self):
        # user_data ={key : value for key, value in request.get_json().items()}
        
        user_data = request.get_json()
        issues = {"errors" : []}
        

        # data validation before it hits the model / db side
        if "username" in user_data:
            if user_data["username"] == "":
                issues["errors"].append("Username is missing")
            else:    
                user_data["user_exist"] = True if User.query.filter(User.username == user_data["username"]).first() else False
                if user_data["user_exist"]:
                    issues["errors"].append("Username already exist. Please log in instead")
        else:
            print(hasattr(user_data, "username"))
            issues["errors"].append("Username is missing")

        if user_data["password"] == "":
            issues["errors"].append("Password is missing")

        # if getattr(user_data, "password_confirmation", False):
        #     if user_data["password"] != user_data["password_confirmation"]:
        #         issues["errors"].append("Passwords do not match.")
        # else:
        #     issues["errors"].append("Password confirmation is missing")


        
        if len(issues["errors"]) > 0:
            print(issues)
            response = make_response(
                jsonify(issues), 
                422
            )
            return response
        
        if not "image_url" in user_data:
            user_data["image_url"] = ""
        if not "bio" in user_data:
            user_data["bio"] = ""

        user = User(
            username=user_data["username"], 
            image_url=user_data["image_url"], 
            bio = user_data["bio"], 
            )
        user.password_hash = user_data["password"]
        
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError as e:
            errorInfo = e.orig.args
            print(errorInfo)
            issues["errors"].append(errorInfo)
            response = make_response(
                jsonify(issues),
                422
            )

        session["user_id"] = user.id
        response = make_response(
            jsonify(user_schema.dump(user)),
            201
        )
        return response

class CheckSession(Resource):
    def get(self):
        if "user_id" in session:
            user_id = session["user_id"]
            if user_id:
                user = User.query.filter(User.id == user_id).first()
                return user_schema.dump(user), 200
        return {}, 401

class Login(Resource):
    
    def post(self):
        user_data = request.get_json()
        issues = {"errors" : []}
        # data validation before it hits the model / db side
        if "username" in user_data:
            if user_data["username"] == "":
                issues["errors"].append("Username is missing")
        else:
            issues["errors"].append("Username is missing")

        if "password" in user_data:
            if user_data["password"] == "":
                issues["errors"].append("Password is missing")
        else:
            issues["errors"].append("Password is missing")

        if len(issues["errors"]) > 0:
            response = make_response(
                jsonify(issues), 
                401
            )
            return response
        
        user = User.query.filter(User.username == user_data["username"]).first()
        if not user:
            issues["errors"].append("You have entered an invalid username or password")
        else:
            if not user.authenticate(user_data["password"]):
                issues["errors"].append("You have entered an invalid username or password")

        if len(issues["errors"]) > 0:
            response = make_response(
                jsonify(issues), 
                401
            )
            return response

        session["user_id"] = user.id
        response = make_response(
            user_schema.dump(user),
            200
        )
        return response
    
class Logout(Resource):
    def delete(self):
        if "user_id" in session:
            if session["user_id"] != None:
                session["user_id"] = None
                return {},204
        return {"errors" : ["No users are loged in"]}, 401
    

class RecipeIndex(Resource):
    def get(self):
        if "user_id" in session:
            recipes = Recipe.query.all()
            response = make_response(
                recipe_many_schema.dump(recipes),
                200
            )
            return response
        return {"errors" : ["No users are loged in"]}, 401


# @app.errorhandler(500)
# def server_issue(e):
#     response = make_response(
#         e,
#         500
#     )
#     return response

# app.register_error_handler(500, server_issue)
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
