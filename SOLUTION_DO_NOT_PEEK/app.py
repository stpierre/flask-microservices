#!/usr/bin/env python
"""Simple REST service for making iostat calls."""

import functools
import logging
import subprocess

import flask
import flask_restful as restful
from flask_restful import fields
from flask_restful import reqparse
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc

from . import models
from . import tasks


app = flask.Flask(__name__)
api = restful.Api(app)

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)


@api.resource("/")
class Versions(restful.Resource):
    """List API versions."""

    def get(self):
        links = []
        for version in (1, 2, 3):
            rel = "v%s" % version
            cls = "EndpointsV%s" % version
            if cls in globals():
                links.append({"rel": rel, "href": api.url_for(globals()[cls])})
        return {"links": links}


@api.resource("/v1/")
class EndpointsV1(restful.Resource):
    """List top-level endpoints"""

    def get(self):
        links = []
        for endpoint in ("Uptime", "IOStat"):
            rel = endpoint.lower()
            cls = "%sV1" % endpoint
            if cls in globals():
                links.append({"rel": rel, "href": api.url_for(globals()[cls])})
        return {"links": links}


@api.resource("/v1/uptime/", endpoint="uptimev1")
@api.resource("/v2/uptime/", endpoint="uptimev2")
class UptimeV1(restful.Resource):
    def get(self):
        cmd = ["uptime"]
        app.logger.info("Calling process: %s", cmd)
        return {"uptime": subprocess.check_output(cmd).strip()}


def get_count_and_wait():
    try:
        count = int(flask.request.args.get("count", 1))
        wait = int(flask.request.args.get("wait", 1))
    except ValueError as err:
        restful.abort(400, msg=str(err))
    if count < 1:
        restful.abort(400, msg="count cannot be less than 1")
    if wait < 1:
        restful.abort(400, msg="wait cannot be less than 1")
    if wait != 1 and count == 1:
        restful.abort(400, msg="Cannot specify wait with count=1")
    return count, wait


@api.resource("/v1/iostat/")
class IOStatV1(restful.Resource):
    def get(self):
        return tasks.iostat.apply(args=get_count_and_wait()).result


@api.resource("/v2/")
class EndpointsV2(restful.Resource):
    """List top-level endpoints"""

    def get(self):
        return {"links": [
            {"rel": "uptime", "href": flask.url_for("uptimev2")},
            {"rel": "iostat", "href": api.url_for(IOStatV2)}]}


def get_task(task_id):
    task = tasks.app.AsyncResult(task_id)
    if task.state == "PENDING":
        restful.abort(404, msg="No such task %s" % task_id)
    return task


@api.resource("/v2/task/<string:task_id>")
class TaskV2(restful.Resource):
    def get(self, task_id):
        task = get_task(task_id)
        retval = {"task_id": task.id,
                  "state": task.state,
                  "links": [
                      {"rel": "self",
                       "href": api.url_for(self.__class__, task_id=task.id)}]}
        if task.ready():
            if isinstance(task.result, BaseException):
                retval["result"] = str(task.result)
            else:
                retval["result"] = task.result
        else:
            retval["links"].append({"rel": "cancel",
                                    "method": "DELETE",
                                    "href": api.url_for(self.__class__,
                                                        task_id=task.id)})
        return retval

    def delete(self, task_id):
        task = get_task(task_id)
        task.revoke()
        return flask.make_response("", 204)


@api.resource("/v2/iostat/")
class IOStatV2(restful.Resource):
    task_resource = TaskV2

    def get(self):
        result = tasks.iostat.delay(*get_count_and_wait())
        return flask.make_response(
            flask.jsonify({"task_id": result.id,
                           "links": [
                               {"rel": "task",
                                "href": api.url_for(self.task_resource,
                                                    task_id=result.id)}]}),
            201)


def get_db_session():
    """Returns a new database connection for the current application context.
    """
    if not hasattr(flask.g, "db_engine"):
        flask.g.db_engine = sqlalchemy.create_engine(models.db_path, echo=True)
    if not hasattr(flask.g, "session_cls"):
        flask.g.session_cls = orm.sessionmaker(bind=flask.g.db_engine)
    if not hasattr(flask.g, "db_session"):
        flask.g.db_session = flask.g.session_cls()
    return flask.g.db_session


class UserLinks(fields.Raw):
    def output(self, key, obj):
        return [
            {"rel": "self",
             "href": api.url_for(UserV3,
                                 username=fields.get_value("username", obj))}]


user_fields = {
    "username": fields.String,
    "fullname": fields.String,
    "admin": fields.Boolean,
    "links": UserLinks
}


@app.teardown_appcontext
def close_db(error):
    """Closes the database at the end of the request."""
    if hasattr(flask.g, 'db_session'):
        flask.g.db_session.close()


def check_auth(username, password):
    """Check if a username/password combination is valid."""
    session = get_db_session()
    try:
        return session.query(models.User).filter_by(
            username=username).filter_by(password=password).one()
    except orm_exc.NoResultFound:
        return False


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return flask.make_response(
        flask.jsonify({"message": "You must login with proper credentials"}),
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def auth_required(func_or_class):
    """Require authentication on a function or all functions in a class."""
    if isinstance(func_or_class, type):
        method_names = ("get", "post", "patch", "put", "delete")
        new_cls = type(func_or_class.__name__, (func_or_class,), {})
        for name in method_names:
            if hasattr(new_cls, name):
                func = getattr(new_cls, name)
                if callable(func):
                    setattr(new_cls, name, _func_auth_required(func))
        return new_cls
    else:
        return _func_auth_required(func_or_class)


def _func_auth_required(func):
    """Decorate a single function as requiring authentication."""
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        auth = flask.request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return func(*args, **kwargs)
    return decorated


def admin_required(func):
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        auth = flask.request.authorization
        if not auth:
            return authenticate()
        user = check_auth(auth.username, auth.password)
        if not user:
            return authenticate()
        if not user.admin:
            restful.abort(403,
                          message="You are not allowed to perform this action")
        return func(*args, **kwargs)
    return decorated


@api.resource("/v3/")
class EndpointsV3(restful.Resource):
    """List top-level endpoints"""

    def get(self):
        return {"links": [
            {"rel": "uptime",
             "href": api.url_for(UptimeV3)},
            {"rel": "iostat",
             "href": api.url_for(IOStatV3)},
            {"rel": "users",
             "href": api.url_for(UsersV3)}]}


@api.resource("/v3/uptime/")
@auth_required
class UptimeV3(UptimeV1):
    pass


@api.resource("/v3/task/<string:task_id>")
@auth_required
class TaskV3(TaskV2):
    pass


@api.resource("/v3/iostat/")
@auth_required
class IOStatV3(IOStatV2):
    task_resource = TaskV3


class UserBase(restful.Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("username", required=True)
    parser.add_argument("fullname", required=True)
    parser.add_argument("password", required=True)
    parser.add_argument("admin", default=False, type=bool)

    def get_user(self, username):
        session = get_db_session()
        try:
            return session.query(models.User).filter_by(username=username).one()
        except orm_exc.NoResultFound:
            return None

    def get_user_or_abort(self, username):
        user = self.get_user(username)
        if user is None:
            restful.abort(404, message="User %s does not exist" % username)
        return user


@api.resource("/v3/users/")
class UsersV3(UserBase):

    @auth_required
    def get(self):
        detailed = bool(flask.request.args.get("detail", False))
        limit = int(flask.request.args.get("limit", -1))
        session = get_db_session()
        if limit > 0:
            users = session.query(models.User)[0:limit]
        else:
            users = session.query(models.User).all()
        if detailed:
            return restful.marshal(users, user_fields, envelope="users")
        else:
            return {"users": [u.username for u in users]}

    @admin_required
    def post(self):
        args = self.parser.parse_args(strict=True)
        if self.get_user(args.username):
            restful.abort(409,
                          message="User %(username)s already exists" % args)

        user = models.User(**args)
        session = get_db_session()
        session.add(user)
        session.commit()

        return flask.make_response(flask.jsonify(restful.marshal(user,
                                                                 user_fields)),
                                   201)


@api.resource("/v3/users/<string:username>")
class UserV3(UserBase):
    patch_parser = reqparse.RequestParser()
    patch_parser.add_argument("username")
    patch_parser.add_argument("password")
    patch_parser.add_argument("fullname")
    patch_parser.add_argument("admin", type=bool)

    def _update_user(self, username, modifications, user=None):
        if user is None:
            user = self.get_user_or_abort(username)

        for key, val in modifications.items():
            if val is not None:
                setattr(user, key, val)

        get_db_session().commit()
        return user

    @auth_required
    @restful.marshal_with(user_fields)
    def get(self, username):
        return self.get_user_or_abort(username)

    @admin_required
    def put(self, username):
        args = self.parser.parse_args(strict=True)
        session = get_db_session()

        user = self.get_user(username)
        if user is None:
            user = models.User(**args)
            session.add(user)
            session.commit()
            code = 201
        else:
            self._update_user(username, args, user=user)
            code = 200
        return flask.make_response(
            flask.jsonify(restful.marshal(user, user_fields)), code)

    @admin_required
    @restful.marshal_with(user_fields)
    def patch(self, username):
        args = self.patch_parser.parse_args(strict=True)
        return self._update_user(username, args)

    @admin_required
    def delete(self, username):
        user = self.get_user_or_abort(username)
        session = get_db_session()
        session.delete(user)
        session.commit()

        return flask.make_response("", 204)
