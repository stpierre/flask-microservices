#!/usr/bin/env python

import base64
import json
import os
import subprocess
import tempfile
import unittest

import ddt
import fixture
import mock
import sqlalchemy
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc

from solution import app
from solution import models

IOSTAT_STYLE_OSX = "Mac OS X"
IOSTAT_STYLE_LINUX = "Linux"
IOSTAT_STYLE = None
try:
    subprocess.check_call(["iostat", "-C"])
    IOSTAT_STYLE = IOSTAT_STYLE_OSX
except subprocess.CalledProcessError:
    IOSTAT_STYLE = IOSTAT_STYLE_LINUX


# TEST_MODULE = "SOLUTION_DO_NOT_PEEK"
TEST_MODULE = "solution"


class UserData(fixture.DataSet):
    class admin:
        username = "stpierre"
        fullname = "Chris St. Pierre"
        password = "hunter2"
        admin = True

    class nonadmin:
        username = "jluser"
        fullname = "J. Random Luser"
        password = "passw0rd"
        admin = False


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        app.app.config["TESTING"] = True
        self.app = app.app.test_client()

    def fetch_json(self, url, code=200, method="get", authenticate=None,
                   **kwargs):
        """Make a request, expecting JSON content and the given code.

        This shortcuts a bunch of commonly-repeated assertions.
        """
        creds = None
        if authenticate == "bad":
            creds = ("fakeuser", "badpassword")
        elif authenticate:
            try:
                user_obj = getattr(UserData, authenticate)
                creds = (user_obj.username, user_obj.password)
            except TypeError:
                creds = authenticate
        if creds:
            kwargs.setdefault("headers", {})
            kwargs["headers"]["Authorization"] = "Basic %s" % (
                base64.b64encode("%s:%s" % creds))
        response = getattr(self.app, method.lower())(url, **kwargs)
        self.assertEqual(response.status_code, code,
                         msg="%s != %s: %s" % (response.status_code, code,
                                               response.get_data()))
        # NOTE(stpierre): JSON redirects are nice, but we won't expect
        # them for this exercise
        if response.get_data() and (code < 300 or code > 399):
            try:
                return json.loads(response.get_data())
            except ValueError as err:
                raise Exception("%s: %s" % (err, response.get_data()))

    def make_path(self, path, **queryargs):
        """Join query args to a path."""
        return "%s?%s" % (
            path, "&".join(
                "%s=%s" % (k, v) for k, v in queryargs.items()))


def has_resource(cls_name):
    """True if the named resource is registered in the API."""
    return cls_name.lower() in app.api.endpoints


def skip_unless_has_resource(cls_name):
    """Skip a test unless the named resource is registered in the API."""
    if not has_resource(cls_name):
        return unittest.skip("%s is not implemented yet" % cls_name)
    else:
        return lambda t: t


@skip_unless_has_resource("Versions")
class TestVersions(BaseTestCase):
    expected = ["v1"]
    possible = ["v2", "v3"]

    def test_version_list(self):
        for version in self.possible:
            if has_resource("endpoints%s" % version):
                self.expected.append(version)
        self.assertDictEqual(self.fetch_json("/"),
                             {"links": [{"rel": "%s" % v, "href": "/%s/" % v}
                                        for v in self.expected]})


@skip_unless_has_resource("EndpointsV1")
class TestEndpointsV1(BaseTestCase):
    def test_endpoint_redirect(self):
        self.fetch_json("/v1", code=301)

    def test_endpoint_list(self):
        links = []
        if has_resource("UptimeV1"):
            links.append({"rel": "uptime", "href": "/v1/uptime/"})
        if has_resource("IOStatV1"):
            links.append({"rel": "iostat", "href": "/v1/iostat/"})
        self.assertDictEqual(self.fetch_json("/v1/"), {"links": links})


@skip_unless_has_resource("UptimeV1")
class TestUptimeV1(BaseTestCase):
    @mock.patch("subprocess.check_output")
    def test_get_uptime(self, mock_check_output):
        mock_check_output.return_value = " fake uptime"
        self.assertDictEqual(self.fetch_json("/v1/uptime/"),
                             {"uptime": "fake uptime"})
        mock_check_output.assert_called_once_with(["uptime"])


@ddt.ddt
@skip_unless_has_resource("IOStatV1")
class TestIOStatV1(BaseTestCase):
    @ddt.data({},
              {"count": 3},
              {"wait": 5, "count": 3})
    @ddt.unpack
    @mock.patch("subprocess.check_output")
    def test_get_iostat(self, mock_check_output, count=1, wait=1):
        mock_check_output.return_value = "fake iostat"

        queryargs = {}
        if count != 1:
            queryargs["count"] = count
        if wait != 1:
            queryargs["wait"] = wait

        self.assertDictEqual(self.fetch_json(self.make_path("/v1/iostat/",
                                                            **queryargs)),
                             {"iostat": "fake iostat"})

        expected = ["iostat", "-d"]
        if IOSTAT_STYLE == IOSTAT_STYLE_OSX:
            expected.extend(["-c", str(count), "-w", str(wait)])
            # NOTE(stpierre): using two assertions instead of
            # assert_called_once_with lets us accept the arguments in
            # any order. It's not perfect -- technically we should
            # look for "iostat", then the other three arguments in any
            # order -- but it's really difficult to make this
            # perfect. Pull requests accepted.
            self.assertItemsEqual(mock_check_output.call_args[0][0],
                                  expected)
            self.assertEqual(mock_check_output.call_count, 1)
        else:
            expected.extend([str(wait), str(count)])
            mock_check_output.assert_called_once_with(expected)

    @ddt.data({"count": -10},
              {"count": 0},
              {"count": 0.5},
              {"wait": 0, "count": 2},
              {"wait": 0.5, "count": 2},
              {"wait": 1.5, "count": 2},
              {"wait": -1, "count": 2},
              {"wait": 2})
    @ddt.unpack
    @mock.patch("subprocess.check_output")
    def test_get_iostat_400(self, mock_check_output, **queryargs):
        self.fetch_json(self.make_path("/v1/iostat/", **queryargs), code=400)


@skip_unless_has_resource("EndpointsV2")
class TestEndpointsV2(BaseTestCase):
    def test_endpoint_list(self):
        links = [{"rel": "uptime", "href": "/v2/uptime/"}]
        if has_resource("IOStatV2"):
            links.append({"rel": "iostat", "href": "/v2/iostat/"})
        self.assertDictEqual(self.fetch_json("/v2/"), {"links": links})


@skip_unless_has_resource("UptimeV2")
class TestUptimeV2(BaseTestCase):
    @mock.patch("subprocess.check_output")
    def test_get_uptime(self, mock_check_output):
        mock_check_output.return_value = " fake uptime"
        self.assertDictEqual(self.fetch_json("/v2/uptime/"),
                             {"uptime": "fake uptime"})
        mock_check_output.assert_called_once_with(["uptime"])


@ddt.ddt
@skip_unless_has_resource("IOStatV2")
class TestIOStatV2(BaseTestCase):
    authenticate = None
    base_url = "/v2/iostat/"
    base_task_url = "/v2/task/"

    @ddt.data({},
              {"count": 3},
              {"wait": 5, "count": 3})
    @ddt.unpack
    @mock.patch("%s.tasks.iostat.delay" % TEST_MODULE)
    def test_get_iostat(self, mock_iostat_delay, count=1, wait=1):
        mock_iostat_delay.return_value = mock.Mock(id="result_id")

        queryargs = {}
        if count != 1:
            queryargs["count"] = count
        if wait != 1:
            queryargs["wait"] = wait

        self.assertDictEqual(
            self.fetch_json(self.make_path(self.base_url, **queryargs),
                            code=201, authenticate=self.authenticate),
            {"task_id": mock_iostat_delay.return_value.id,
             "links": [{
                 "rel": "task",
                 "href": "%s%s" % (self.base_task_url,
                                   mock_iostat_delay.return_value.id)}]})

        mock_iostat_delay.assert_called_once_with(count, wait)

    @ddt.data({"count": -10},
              {"count": 0},
              {"count": 0.5},
              {"wait": 0, "count": 2},
              {"wait": 0.5, "count": 2},
              {"wait": 1.5, "count": 2},
              {"wait": -1, "count": 2},
              {"wait": 2})
    @ddt.unpack
    @mock.patch("%s.tasks.iostat.delay" % TEST_MODULE)
    def test_get_iostat_400(self, mock_iostat_delay, **queryargs):
        self.fetch_json(self.make_path(self.base_url, **queryargs),
                        authenticate=self.authenticate, code=400)


@ddt.ddt
@skip_unless_has_resource("TaskV2")
class TestTaskV2(BaseTestCase):
    authenticate = None
    base_url = "/v2/task/"

    def setUp(self):
        super(TestTaskV2, self).setUp()
        self.task_id = "task_id"
        self.path = "%s%s" % (self.base_url, self.task_id)
        self.uri = self.make_path(self.path)

    def _make_async_result(self, status, result=None):
        retval = mock.Mock()
        retval.id = self.task_id
        if status in ["FAILURE", "SUCCESS"]:
            retval.ready.return_value = True
            retval.result = retval.info = result
            retval.get.return_value = retval.collect.return_value = \
                retval.wait.return_value = result
        else:
            retval.ready.return_value = False
        retval.failed.return_value = status == "FAILURE"
        retval.successful.return_value = not retval.failed.return_value
        retval.state = retval.status = status
        return retval

    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_get_task_ready(self, mock_AsyncResult):
        mock_AsyncResult.return_value = self._make_async_result("SUCCESS",
                                                                "output")
        self.assertDictEqual(self.fetch_json(self.uri,
                                             authenticate=self.authenticate),
                             {"task_id": self.task_id,
                              "state": "SUCCESS",
                              "links": [{"rel": "self", "href": self.path}],
                              "result": "output"})
        mock_AsyncResult.assert_called_once_with(self.task_id)

    @ddt.data({"status": "STARTED"},
              {"status": "RETRY"},
              {"status": "QUEUED"})
    @ddt.unpack
    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_get_task_running(self, mock_AsyncResult, status="STARTED"):
        mock_AsyncResult.return_value = self._make_async_result(status,
                                                                "output")
        self.assertDictEqual(self.fetch_json(self.uri,
                                             authenticate=self.authenticate),
                             {"task_id": self.task_id,
                              "state": status,
                              "links": [{"rel": "self", "href": self.path},
                                        {"rel": "cancel",
                                         "method": "DELETE",
                                         "href": self.path}]})
        mock_AsyncResult.assert_called_once_with(self.task_id)

    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_get_task_404(self, mock_AsyncResult):
        mock_AsyncResult.return_value = self._make_async_result("PENDING")
        self.fetch_json(self.uri, code=404, authenticate=self.authenticate)
        mock_AsyncResult.assert_called_once_with(self.task_id)

    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_get_task_error(self, mock_AsyncResult):
        result = Exception("message")
        mock_AsyncResult.return_value = self._make_async_result("FAILURE",
                                                                result)
        self.assertDictEqual(self.fetch_json(self.uri,
                                             authenticate=self.authenticate),
                             {"task_id": self.task_id,
                              "state": "FAILURE",
                              "result": "message",
                              "links": [{"rel": "self", "href": self.path}]})
        mock_AsyncResult.assert_called_once_with(self.task_id)

    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_delete_task(self, mock_AsyncResult):
        mock_AsyncResult.return_value = self._make_async_result("QUEUED")
        self.fetch_json(self.uri, method="DELETE", code=204,
                        authenticate=self.authenticate)
        mock_AsyncResult.assert_called_once_with(self.task_id)
        mock_AsyncResult.return_value.revoke.assert_called_once_with()

    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_delete_task_404(self, mock_AsyncResult):
        mock_AsyncResult.return_value = self._make_async_result("PENDING")
        self.fetch_json(self.uri, method="DELETE", code=404,
                        authenticate=self.authenticate)
        mock_AsyncResult.assert_called_once_with(self.task_id)


class DBTestCase(BaseTestCase):
    def setUp(self):
        super(DBTestCase, self).setUp()

        self.db_file = tempfile.mkstemp()[1]
        self.engine = sqlalchemy.create_engine("sqlite:///%s" % self.db_file)
        self.session_cls = orm.sessionmaker(bind=self.engine)
        self.session = self.session_cls()

        self.fixture = fixture.SQLAlchemyFixture(env={"UserData": models.User},
                                                 engine=self.engine)
        self.fixture_data = self.fixture.data(UserData)
        models.Base.metadata.create_all(self.engine)
        self.fixture_data.setup()

        self.db_patcher = mock.patch("%s.app.get_db_session" % TEST_MODULE,
                                     return_value=self.session)
        self.db_patcher.start()

    def tearDown(self):
        self.db_patcher.stop()

        try:
            os.unlink(self.db_file)
        except Exception as err:
            print("Could not remove database file %s: %s" % (self.db_file, err))

    def marshal_fixture(self, user):
        return {"username": user.username,
                "fullname": user.fullname,
                "admin": user.admin,
                "links": [{"rel": "self",
                           "href": "/v3/users/%s" % user.username}]}


@skip_unless_has_resource("EndpointsV3")
class TestEndpointsV3(BaseTestCase):
    def test_endpoint_list(self):
        if has_resource("UptimeV3"):
            links = [{"rel": "uptime", "href": "/v3/uptime/"}]
        if has_resource("IOStatV3"):
            links.append({"rel": "iostat", "href": "/v3/iostat/"})
        if has_resource("UsersV3"):
            links.append({"rel": "users", "href": "/v3/users/"})
        self.assertDictEqual(self.fetch_json("/v3/"), {"links": links})


@ddt.ddt
@skip_unless_has_resource("UptimeV3")
class TestUptimeV3(DBTestCase):
    @ddt.data({"authenticate": None},
              {"authenticate": "bad"})
    @ddt.unpack
    def test_get_uptime_unauth(self, authenticate=None):
        self.fetch_json("/v3/uptime/", authenticate=authenticate, code=401)

    @ddt.data({"authenticate": "nonadmin"},
              {"authenticate": "admin"})
    @ddt.unpack
    @mock.patch("subprocess.check_output")
    def test_get_uptime(self, mock_check_output, authenticate=None):
        mock_check_output.return_value = " fake uptime"
        self.assertDictEqual(self.fetch_json("/v3/uptime/",
                                             authenticate=authenticate),
                             {"uptime": "fake uptime"})
        mock_check_output.assert_called_once_with(["uptime"])


@ddt.ddt
@skip_unless_has_resource("IOStatV3")
class TestIOStatV3(TestIOStatV2, DBTestCase):
    authenticate = "nonadmin"
    base_url = "/v3/iostat/"
    base_task_url = "/v3/task/"

    @ddt.data({"authenticate": None},
              {"authenticate": "bad"})
    @ddt.unpack
    def test_get_iostat_unauth(self, authenticate=None):
        self.fetch_json("/v3/iostat/", authenticate=authenticate, code=401)


@ddt.ddt
@skip_unless_has_resource("TaskV3")
class TestTaskV3(TestTaskV2, DBTestCase):
    authenticate = "nonadmin"
    base_url = "/v3/task/"

    @ddt.data({"authenticate": None},
              {"authenticate": "bad"})
    @ddt.unpack
    @mock.patch("%s.tasks.app.AsyncResult" % TEST_MODULE)
    def test_get_task_ready_unauth(self, mock_AsyncResult, authenticate=None):
        mock_AsyncResult.return_value = self._make_async_result("SUCCESS",
                                                                "output")
        self.fetch_json(self.uri, authenticate=authenticate, code=401)


@ddt.ddt
@skip_unless_has_resource("UsersV3")
class TestUsersV3(DBTestCase):

    @ddt.data({"method": "GET"},
              {"authenticate": "bad", "method": "GET"},
              {"method": "POST"},
              {"authenticate": "bad", "method": "POST"})
    @ddt.unpack
    def test_users_operation_unauth(self, authenticate=None, method=None):
        self.fetch_json("/v3/users/", method=method, authenticate=authenticate,
                        code=401)

    def test_list_users(self):
        actual = self.fetch_json("/v3/users/", authenticate="nonadmin")
        expected = {"users": [getattr(UserData, u).username
                              for u in ["admin", "nonadmin"]]}
        self.assertItemsEqual(actual, expected)

    def test_list_users_limit(self):
        actual = self.fetch_json("/v3/users/?limit=1", authenticate="nonadmin")
        # NOTE(stpierre): we don't care which user is in the result as
        # long as exactly one is
        matches = 0
        for usertype in ["admin", "nonadmin"]:
            user = getattr(UserData, usertype)
            try:
                self.assertDictEqual(actual, {"users": [user.username]})
                matches += 1
            except AssertionError:
                pass
        self.assertEqual(matches, 1)

    def test_list_users_detailed(self):
        actual = self.fetch_json("/v3/users/?detail=1", authenticate="nonadmin")
        expected = {"users": []}
        for usertype in ["admin", "nonadmin"]:
            user = getattr(UserData, usertype)
            expected["users"].append(
                {"username": user.username,
                 "fullname": user.fullname,
                 "admin": user.admin,
                 "links": {"rel": "self",
                           "href": "/v3/users/%s" % user.username}})
        self.assertItemsEqual(actual, expected)

    def test_create_user_nonadmin(self):
        self.fetch_json("/v3/users/", method="POST", authenticate="nonadmin",
                        code=403)

    def test_create_user(self):
        userdata = {"username": "test_user",
                    "password": "password",
                    "fullname": "fullname",
                    "admin": True}
        actual = self.fetch_json("/v3/users/", method="POST", data=userdata,
                                 authenticate="admin", code=201)

        expected = dict(userdata)
        del expected["password"]
        expected["links"] = [{"rel": "self",
                              "href": "/v3/users/%(username)s" % userdata}]
        self.assertDictEqual(actual, expected)

        # read our writes
        self.assertIn(
            userdata["username"],
            self.fetch_json("/v3/users/", authenticate="nonadmin")["users"])
        self.assertDictEqual(
            expected,
            self.fetch_json("/v3/users/%(username)s" % userdata,
                            authenticate="nonadmin"))

    def test_create_user_duplicate(self):
        userdata = {"username": UserData.admin.username,
                    "password": "password",
                    "fullname": "fullname"}
        self.fetch_json("/v3/users/", method="POST", data=userdata,
                        authenticate="admin", code=409)

    @ddt.data({},
              {"username": "username", "password": "password"},
              {"username": "username", "password": "password", "admin": True},
              {"username": "username", "fullname": "fullname"},
              {"fullname": "fullname", "password": "password"},
              {"username": "username"})
    def test_create_user_incomplete(self, userdata):
        self.fetch_json("/v3/users/", method="POST", data=userdata,
                        authenticate="admin", code=400)


@ddt.ddt
@skip_unless_has_resource("UserV3")
class TestUserV3(DBTestCase):

    @ddt.data({"method": "GET"},
              {"method": "GET", "authenticate": "bad"},
              {"method": "PUT"},
              {"method": "PUT", "authenticate": "bad"},
              {"method": "PATCH"},
              {"method": "PATCH", "authenticate": "bad"},
              {"method": "DELETE"},
              {"method": "DELETE", "authenticate": "bad"})
    @ddt.unpack
    def test_user_operation_unauth(self, method="GET", authenticate=None):
        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        method=method,
                        authenticate=authenticate, code=401)

    @ddt.data({"method": "PUT"},
              {"method": "PATCH"},
              {"method": "DELETE"})
    @ddt.unpack
    def test_user_operation_nonadmin(self, method=None):
        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        method=method, authenticate="nonadmin",
                        code=403)

    @ddt.data({"method": "GET"},
              {"method": "PATCH"},
              {"method": "DELETE"})
    @ddt.unpack
    def test_user_operation_nonexistent(self, method=None):
        self.fetch_json("/v3/users/not-a-real-user", method=method,
                        authenticate="admin", code=404)

    @ddt.data({},
              {"username": "username", "password": "password"},
              {"username": "username", "password": "password", "admin": True},
              {"username": "username", "fullname": "fullname"},
              {"fullname": "fullname", "password": "password"},
              {"username": "username"})
    def test_put_user_incomplete(self, userdata):
        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        method="PUT", data=userdata, authenticate="admin",
                        code=400)

    def test_get_user(self):
        self.assertDictEqual(
            self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                            authenticate="nonadmin"),
            self.marshal_fixture(UserData.nonadmin))

    def test_put_user_update(self):
        old_username = UserData.nonadmin.username
        userdata = {"username": "new_username",
                    "password": "new_password",
                    "fullname": "fullname",
                    "admin": True}
        actual = self.fetch_json("/v3/users/%s" % old_username,
                                 method="PUT", data=userdata,
                                 authenticate="admin")

        expected = dict(userdata)
        del expected["password"]
        expected["links"] = [{"rel": "self",
                              "href": "/v3/users/new_username"}]
        self.assertDictEqual(actual, expected)

        # read our writes
        self.assertDictEqual(
            expected,
            self.fetch_json(
                "/v3/users/%(username)s" % userdata,
                authenticate=("new_username", "new_password")))

    def test_put_user_create(self):
        userdata = {"username": "test_user",
                    "password": "password",
                    "fullname": "fullname",
                    "admin": True}
        actual = self.fetch_json("/v3/users/%(username)s" % userdata,
                                 method="PUT", data=userdata,
                                 authenticate="admin", code=201)

        expected = dict(userdata)
        del expected["password"]
        expected["links"] = [{"rel": "self",
                              "href": "/v3/users/%(username)s" % userdata}]
        self.assertDictEqual(actual, expected)

        # read our writes
        self.assertIn(
            userdata["username"],
            self.fetch_json("/v3/users/", authenticate="nonadmin")["users"])
        self.assertDictEqual(
            expected,
            self.fetch_json("/v3/users/%(username)s" % userdata,
                            authenticate="nonadmin"))

    @ddt.data({"username": "new_username"},
              {"password": "new_password"},
              {"fullname": "New Fullname"},
              {"admin": True},
              {"username": "new_username", "password": "new_password",
               "fullname": "New Fullname", "admin": True})
    def test_patch_user(self, userdata):
        old_username = UserData.nonadmin.username
        new_username = userdata.get("username", old_username)

        actual = self.fetch_json("/v3/users/%s" % old_username,
                                 method="PATCH", data=userdata,
                                 authenticate="admin")

        expected = self.marshal_fixture(UserData.nonadmin)
        expected.update(userdata)
        if "username" in userdata:
            expected["links"][0]["href"] = "/v3/users/%s" % new_username
        if "password" in expected:
            del expected["password"]
        self.assertDictEqual(actual, expected)

        # read our writes
        password = userdata.get("password", UserData.nonadmin.password)
        self.assertDictEqual(
            expected,
            self.fetch_json("/v3/users/%s" % new_username,
                            authenticate=(new_username, password)))

    def test_delete_user(self):
        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        method="DELETE", authenticate="admin", code=204)

        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        authenticate="nonadmin", code=401)
        self.fetch_json("/v3/users/%s" % UserData.nonadmin.username,
                        authenticate="admin", code=404)
        self.assertNotIn(
            UserData.nonadmin.username,
            self.fetch_json("/v3/users/", authenticate="admin")["users"])


if __name__ == "__main__":
    unittest.main()
