from flask_restful import Resource

class InfobloxViews(Resource):
    def get(self):
        return ["WLP-default-internal", "WLP-Internet"]
