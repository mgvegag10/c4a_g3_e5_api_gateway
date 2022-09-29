from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

app=Flask(__name__)
cors = CORS(app)
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que sea conveniente
jwt = JWTManager(app)
@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "El nombre de usuario o contraseña son incorrectos"}), 400

@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        print(type(usuario))
        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"])
            if not tienePersmiso:
                return jsonify({"message": "Permiso denegado"}), 401
        else:
            return jsonify({"message": "Permiso denegado"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url
def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "metodo":metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso

###################################################################################
#   REDIRECCIONAR CRUD CANDIDATOS
###################################################################################
@app.route("/candidatos",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


###################################################################################
#   REDIRECCIONAR CRUD USUARIOS
###################################################################################
@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios",methods=['POST'])
def crearUsuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarUsuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>/rol/<string:id>",methods=['PUT'])
def modificarUsuarioRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-users"] + '/usuarios/' + id + '/rol/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

###################################################################################
#   REDIRECCIONAR CRUD ROLES
###################################################################################
@app.route("/roles",methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-roles"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/roles",methods=['POST'])
def crearRol():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-roles"] + '/roles'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>",methods=['GET'])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-roles"] + '/roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>",methods=['PUT'])
def modificarRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-roles"] + '/roles/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>",methods=['DELETE'])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-roles"] + '/roles/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###################################################################################
#   REDIRECCIONAR CRUD PERMISOS
###################################################################################
@app.route("/permisos",methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-permisos"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos",methods=['POST'])
def crearPermiso():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-permisos"] + '/permisos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['GET'])
def getPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-permisos"] + '/permisos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['PUT'])
def modificarPermiso(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-permisos"] + '/permisos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['DELETE'])
def eliminarPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-permisos"] + '/permisos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
###################################################################################
#   REDIRECCIONAR CRUD MESAS
###################################################################################
@app.route("/mesas",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mesas"] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mesas"] + '/mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mesas"] + '/mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/permisos/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mesas"] + '/mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['DELETE'])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mesas"] + '/mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
