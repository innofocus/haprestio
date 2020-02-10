#!/usr/bin/env python3

# pres side
from functools import wraps
from flask import Flask, jsonify, url_for, Response, Blueprint, redirect, request
from flask_restplus import Api, Resource, fields, marshal
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, verify_jwt_in_request, get_jwt_claims
)

# data side
import consul
import yaml
import os
import time

import datetime
import bcrypt
import subprocess
import requests
import csv
import json


from . import *

####
# temp token


@app.route('/')
def Redirect_slash():
    return redirect(app.config['DEFAULT_LOCATION'], code=302)

@app.route('/maintenance')
def Maintenance():
    return Response(json.dumps({"message": "the api is in maintenance mode"}),
                    status=503,
                    mimetype='application/json')

@app.route('/pages/releasenotes')
def ReleaseNotes():
    return Response(releasenotes, status=200, mimetype='text/plain')


########
# adm and ops


def main():
    # modules
    from .operations import parser, install

    if parser.args.install:
        install.templates(parser.args)
        install.deploy()
        exit(0)

    from . import api_v1
    api_v1.init()

    from . import adm_v1
    adm_v1.init()

    if app.config['DEBUG']:
        app.run(debug=True, host=app.config['HOST'], port=app.config['PORT'])
    else:
        app.run(host=app.config['HOST'], port=app.config['PORT'])