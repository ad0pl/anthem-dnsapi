from flask_restful import Resource, reqparse, fields, marshal_with

class InfobloxViews(Resource):
    def get(self):
        return ["WLP-default-internal", "do-not-use"]
