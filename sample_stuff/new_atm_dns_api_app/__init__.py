import json
from new_atm_dns_api_app.app import create_app

(app, api) = create_app()

@app.errorhandler(401)
def user_not_auth(error):
    ret = { 'status': "error", 'message': error }
    return json.dumps(ret), 401

@app.errorhandler(403)
def user_bad_auth(error):
    ret = { 'status': "error", 'message': error }
    return json.dumps(ret), 403

@app.errorhandler(404)
def obj_not_found(error):
    ret = { 'status': "error", 'message': error }
    return json.dumps(ret), 404

if __name__ == '__main__':
    print("Hello from __main__")
    app.run(host="0.0.0.0", debug=True)

