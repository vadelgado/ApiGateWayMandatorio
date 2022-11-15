from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import datetime
import requests
import re


app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)

@app.before_request
def before_request_callback():#callback:Traer devuelta
    endPoint = limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        print("ruta excluida ", request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePermiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def validarPermiso(endPoint,metodo,idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, headers=headers, json=body)
    try:
        data = response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso

def limpiarURL(url):
    partes= request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)

########################################redireccionamiento Resultado####################################################
@app.route("/resultado", methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#Añadir un Resultado a la Mesa
@app.route("/resultado/mesa/<string:id_mesa>/candidato/<string:id_candidato>", methods=['POST'])
def crearResultado(id_mesa, id_candidato):
    data = request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/mesa/' + id_mesa + '/candidato/' + id_candidato
    response =  requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

#Obtener Resultado Específico
@app.route("/resultado/<string:id>", methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# Modificar Un resultado

@app.route("/resultado/<string:id>/mesa/<string:id_mesa>/candidato/<string:id_candidato>", methods=['PUT'])
def modificarResultado(id, id_mesa, id_candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/' + id + '/mesa/' + id_mesa + '/candidato/' + id_candidato
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

# Eliminar un Resultado

@app.route("/resultado/<string:id_resultado>", methods=['DELETE'])
def eliminarResultado(id_resultado):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/' +id_resultado
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#Buscar los candidatos votados en una determinada Mesa
@app.route("/resultado/mesa/<string:id_mesa>", methods={'GET'})
def inscritosMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/mesa/' + id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/candidato/<string:id_candidato>", methods={'GET'})
def inscritoEnMesa(id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/candidato/' + id_candidato
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultado/candidato/votos/<string:id_candidato>",methods={'GET'})
def getvotosCandidato(id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/resultado/candidato/votos/' + id_candidato
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

########################################redireccionamiento Resultado####################################################

########################################redireccionamiento Partido######################################################
@app.route("/partido", methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/partido'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partido", methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/partido'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partido/<string:id_partido>", methods=['GET'])
def getPartido(id_partido):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/partido/' + id_partido
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partido/<string:id_partido>", methods=['PUT'])
def modificarPartido(id_partido):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/partido/' + id_partido
    response = requests.put(url, headers=headers, json=data)
    json =response.json()
    return jsonify(json)

@app.route("/partido/<string:id_partido>", methods=['DELETE'])
def eliminarPartido(id_partido):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/partido/' + id_partido
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

########################################redireccionamiento Partido######################################################

########################################redireccionamiento Candidato####################################################

@app.route("/candidato/<string:id>/partido/<string:id_partido>", methods=['PUT'])
def asignarPartidoACandidato(id, id_partido):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato/' + id + '/partido/' + id_partido
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato", methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato", methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/candidato/<string:id>", methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>", methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidato/<string:id>", methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/candidato/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

########################################redireccionamiento Candidato####################################################


########################################redireccionamiento Mesa#########################################################
@app.route("/mesa", methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/mesa'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa", methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/mesa'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id_mesa>", methods=['GET'])
def getMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/mesa/' + id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa/<string:id_mesa>", methods=['PUT'])
def modificarMesa(id_mesa):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/mesa/' + id_mesa
    response = requests.put(url, headers=headers, json=data)
    json =response.json()
    return jsonify(json)

@app.route("/mesa/<string:id_mesa>", methods=['DELETE'])
def eliminarMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-mandatoriano"] + '/mesa/' + id_mesa
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
########################################Redireccionamiento Mesa#########################################################


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])