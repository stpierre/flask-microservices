#!/usr/bin/env python
"""Simple REST service for making iostat calls."""

import subprocess

import flask
import flask_restful as restful

from . import tasks

app = flask.Flask(__name__)
api = restful.Api(app)


@api.resource("/")
class Versions(restful.Resource):
    """List API versions."""

    def get(self):
        links = []
        for version in (1, 2):
            rel = "v%s" % version
            cls = "EndpointsV%s" % version
            if cls in globals():
                links.append({"rel": rel, "href": api.url_for(globals()[cls])})
        return {"links": links}


@api.resource("/v1/")
class EndpointsV1(restful.Resource):
    """List top-level endpoints"""

    def get(self):
        links = [{"rel": "uptime", "href": api.url_for(UptimeV1)}]
        if "IOStatV1" in globals():
            links.append({"rel": "iostat", "href": api.url_for(IOStatV1)})
        return {"links": links}


@api.resource("/v1/uptime/")
class UptimeV1(restful.Resource):
    def get(self):
        pass  # TODO: your implementation here
