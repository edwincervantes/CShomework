from flask import Flask
from flask_restful import Resource, reqparse ,Api

TGS = Flask(__name__)
api = Api(TGS)

articles = [
    {
        "name": "EJ",
        "age": 21,
        "occupation": "Student"
} 
]

class Article(Resource):
    def get(self, name):
        for article in articles:
            if(name == article["name"]):
                return article, 200
        return "name not found", 404

    def post(self, name):
        parser = reqparse.RequestParser()
        parser.add_argument("age")
        parser.add_argument("occupation")
        args = parser.parse_args()

        article = {
            "name": name,
            "age": args["age"],
            "occupation": args["occupation"]
        }
        articles.append(article)
        return article, 201

    def put(self, name):
        parser = reqparse.RequestParser()
        parser.add_argument("age")
        parser.add_argument("occupation")
        args = parser.parse_args()

        for article in articles:
            if(name == article["name"]):
                article["age"] = args["age"]
                article["occupation"] = args["occupation"]
                return article, 200

        article = {
            "name": name,
            "age": args["age"],
            "occupation": args["occupation"]
        }
        articles.append(article)
        return article, 201

    def delete(self, name):
        global articles
        articles = [article for article in articles if article["name"] != name]
        return "{} is deleted.".format(name), 200

api.add_resource(Article, "/name/<string:name>")

TGS.run(debug=True,port=8080)
