"""Black-box tests against a running server. Standard library only.

    cargo run --bin seed && cargo run      # in one terminal
    python3 -m unittest -v tests/test_api.py

Needs BASE_URL (default http://127.0.0.1:3000), ADMIN_EMAIL and ADMIN_PASSWORD,
taken from the environment or from .env. Roles are set through the admin API.
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import random
import time
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit

env_file = Path(__file__).resolve().parent.parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        k, sep, v = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            os.environ.setdefault(k.strip(), v.strip())

BASE = urlsplit(os.environ.get("BASE_URL", "http://127.0.0.1:3000"))


def random_ip():
    # The login limiter keys on the client IP, so each client gets its own loopback address.
    # shortcut: needs Linux (all of 127.0.0.0/8 is loopback), on macOS alias the addresses first.
    return f"127.{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def call(method, path, token=None, body=None, ip=None):
    """Returns (status, parsed JSON body or None)."""
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, source_address=(ip or random_ip(), 0))
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body)
    try:
        conn.request(method, path, data, headers)
        res = conn.getresponse()
        raw = res.read()
    finally:
        conn.close()
    try:
        return res.status, json.loads(raw)
    except ValueError:
        return res.status, None


def register(tag):
    """Registers a user and returns (id, email)."""
    email = f"{tag}-{uuid.uuid4()}@example.com"
    s, b = call("POST", "/auth/register", body={"email": email, "password": "password123", "full_name": tag})
    assert s == 201, b
    return b["id"], email


def login(email, password="password123"):
    s, b = call("POST", "/auth/login", body={"email": email, "password": password})
    assert s == 200, b
    return b


def sign_jwt(claims, secret):
    """An HS256 JWT, built by hand so the tests can make expired or wrongly signed tokens."""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


_admin_token = None


def admin_token():
    global _admin_token
    if _admin_token is None:
        _admin_token = login(os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"])["access_token"]
    return _admin_token


def user(role):
    """A registered user with the given role, plus their access token."""
    uid, email = register(role)
    if role != "member":
        s, b = call("PATCH", f"/users/{uid}/role", admin_token(), {"role": role})
        assert s == 200, b
    return uid, login(email)["access_token"]


class ApiTest(unittest.TestCase):
    def test_register_login_me_and_no_password_leak(self):
        _, email = register("alice")
        tokens = login(email)
        s, me = call("GET", "/auth/me", tokens["access_token"])
        self.assertEqual(s, 200)
        self.assertEqual(me["email"], email)
        self.assertNotIn("password", json.dumps(me))
        self.assertEqual(me["role"], "member")

    def test_missing_expired_and_forged_tokens_are_401(self):
        uid, _ = register("tok")
        secret = os.environ["JWT_SECRET"]
        now = int(time.time())
        good = sign_jwt({"sub": uid, "iat": now, "exp": now + 600}, secret)
        expired = sign_jwt({"sub": uid, "iat": now - 7200, "exp": now - 3600}, secret)
        forged = sign_jwt({"sub": uid, "iat": now, "exp": now + 600}, "not-the-server-secret-at-all-xxxx")

        # The hand-made token works when it is valid, so the 401s below are about expiry and signature.
        self.assertEqual(call("GET", "/auth/me", good)[0], 200)
        for token in (None, "garbage", expired, forged):
            s, b = call("GET", "/auth/me", token)
            self.assertEqual((s, b["error"]["code"]), (401, "UNAUTHORIZED"), token)

    def test_every_error_uses_the_json_shape(self):
        _, token = user("member")
        s, b = call("GET", "/no-such-route", token)
        self.assertEqual((s, b["error"]["code"]), (404, "NOT_FOUND"))
        s, b = call("GET", "/projects/not-a-uuid", token)
        self.assertEqual((s, b["error"]["code"]), (400, "BAD_REQUEST"))

    def test_duplicate_email_is_409_and_bad_input_is_422(self):
        _, email = register("dup")
        body = {"email": email, "password": "password123", "full_name": "x"}
        self.assertEqual(call("POST", "/auth/register", body=body)[0], 409)
        s, b = call("POST", "/auth/register", body={"email": "nope", "password": "short", "full_name": ""})
        self.assertEqual(s, 422)
        self.assertNotIn("short", json.dumps(b), "must not echo the password")

    def test_wrong_password_and_unknown_email_look_identical(self):
        _, email = register("who")
        wrong = call("POST", "/auth/login", body={"email": email, "password": "wrongpass1"})
        unknown = call("POST", "/auth/login", body={"email": "ghost@example.com", "password": "wrongpass1"})
        self.assertEqual(wrong[0], 401)
        self.assertEqual(wrong, unknown)

    def test_refresh_rotates_and_reuse_revokes_everything(self):
        _, email = register("rot")
        r1 = login(email)["refresh_token"]
        s, second = call("POST", "/auth/refresh", body={"refresh_token": r1})
        self.assertEqual(s, 200)
        r2 = second["refresh_token"]
        self.assertNotEqual(r1, r2)
        # Replaying the old token is theft: 401, and the new token dies too.
        self.assertEqual(call("POST", "/auth/refresh", body={"refresh_token": r1})[0], 401)
        self.assertEqual(call("POST", "/auth/refresh", body={"refresh_token": r2})[0], 401)

    def test_login_is_rate_limited(self):
        ip = random_ip()
        statuses = [
            call("POST", "/auth/login", body={"email": "x@example.com", "password": "wrongpass1"}, ip=ip)[0]
            for _ in range(8)
        ]
        self.assertEqual(statuses[-1], 429)

    def test_register_is_rate_limited(self):
        ip = random_ip()
        statuses = [
            call("POST", "/auth/register", body={"email": "nope", "password": "x", "full_name": ""}, ip=ip)[0]
            for _ in range(8)
        ]
        self.assertEqual(statuses[-1], 429)

    def test_password_change_ends_every_session(self):
        _, email = register("pw")
        tokens = login(email)
        access, refresh = tokens["access_token"], tokens["refresh_token"]

        s, _ = call("PUT", "/auth/me/password", access, {"current_password": "wrongpass1", "new_password": "newpassword1"})
        self.assertEqual(s, 400)
        s, _ = call("PUT", "/auth/me/password", access, {"current_password": "password123", "new_password": "newpassword1"})
        self.assertEqual(s, 204)

        self.assertEqual(call("POST", "/auth/refresh", body={"refresh_token": refresh})[0], 401)
        self.assertEqual(call("POST", "/auth/login", body={"email": email, "password": "password123"})[0], 401)
        login(email, "newpassword1")

    def test_member_removal_unassigns_and_deletes_and_null_clears(self):
        _, m1 = user("manager")
        alice_id, alice = user("member")
        _, p = call("POST", "/projects", m1, {"name": "Beta", "description": "about beta"})
        pid = p["id"]
        call("POST", f"/projects/{pid}/members", m1, {"user_id": alice_id})
        _, task = call("POST", f"/projects/{pid}/tasks", m1, {"title": "A", "description": "d", "assignee_id": alice_id})
        tid = task["id"]

        # absent keeps the description, null clears it
        s, b = call("PATCH", f"/tasks/{tid}", m1, {"title": "A2"})
        self.assertEqual((s, b["description"]), (200, "d"))
        s, b = call("PATCH", f"/tasks/{tid}", m1, {"description": None})
        self.assertEqual((s, b["description"]), (200, None))
        s, b = call("PATCH", f"/projects/{pid}", m1, {"description": None})
        self.assertEqual((s, b["name"], b["description"]), (200, "Beta", None))

        # removing alice unassigns her task and hides the project from her
        self.assertEqual(call("DELETE", f"/projects/{pid}/members/{alice_id}", m1)[0], 204)
        self.assertIsNone(call("GET", f"/tasks/{tid}", m1)[1]["assignee_id"])
        self.assertEqual(call("GET", f"/projects/{pid}", alice)[0], 404)
        self.assertEqual(call("DELETE", f"/projects/{pid}/members/{alice_id}", m1)[0], 404)

        self.assertEqual(call("DELETE", f"/tasks/{tid}", m1)[0], 204)
        self.assertEqual(call("GET", f"/tasks/{tid}", m1)[0], 404)
        self.assertEqual(call("DELETE", f"/projects/{pid}", m1)[0], 204)
        self.assertEqual(call("GET", f"/projects/{pid}", m1)[0], 404)

    def test_permissions_and_visibility(self):
        _, member = user("member")
        m1_id, m1 = user("manager")
        _, m2 = user("manager")
        alice_id, alice = user("member")
        _, stranger = user("member")

        # member can't create a project
        self.assertEqual(call("POST", "/projects", member, {"name": "n"})[0], 403)

        s, p = call("POST", "/projects", m1, {"name": "Alpha"})
        self.assertEqual(s, 201)
        self.assertEqual(p["owner_id"], m1_id)
        pid = p["id"]

        # another manager, and a stranger, can't even see it
        self.assertEqual(call("PATCH", f"/projects/{pid}", m2, {"name": "x"})[0], 404)
        self.assertEqual(call("GET", f"/projects/{pid}", stranger)[0], 404)

        self.assertEqual(call("POST", f"/projects/{pid}/members", m1, {"user_id": alice_id})[0], 201)
        # the list shows it to the member, not to the stranger
        list_ids = lambda token: [p["id"] for p in call("GET", "/projects?limit=100", token)[1]["data"]]
        self.assertIn(pid, list_ids(alice))
        self.assertNotIn(pid, list_ids(stranger))

        # a member sees it but can't edit it
        self.assertEqual(call("GET", f"/projects/{pid}", alice)[0], 200)
        self.assertEqual(call("PATCH", f"/projects/{pid}", alice, {"name": "x"})[0], 403)

        # tasks: assignee can change status, others can't
        s, task = call("POST", f"/projects/{pid}/tasks", m1, {"title": "A", "assignee_id": alice_id})
        self.assertEqual(s, 201)
        tid = task["id"]
        s, b = call("PATCH", f"/tasks/{tid}/status", alice, {"status": "in_progress"})
        self.assertEqual((s, b["status"]), (200, "in_progress"))
        self.assertEqual(call("PATCH", f"/tasks/{tid}/status", stranger, {"status": "done"})[0], 404)
        self.assertEqual(call("PATCH", f"/tasks/{tid}", alice, {"title": "x"})[0], 403)

        # a project member can't change the status of a task assigned to someone else
        _, other = call("POST", f"/projects/{pid}/tasks", m1, {"title": "C", "assignee_id": m1_id})
        self.assertEqual(call("PATCH", f"/tasks/{other['id']}/status", alice, {"status": "done"})[0], 403)

        # assignee must belong to the project
        s, _ = call("POST", f"/projects/{pid}/tasks", m1, {"title": "B", "assignee_id": str(uuid.uuid4())})
        self.assertEqual(s, 422)

    def test_admin_deactivation_kills_the_token_and_pagination_is_clamped(self):
        admin = admin_token()
        victim_id, victim = user("member")

        s, b = call("GET", "/projects?limit=100000", admin)
        self.assertEqual((s, b["meta"]["limit"]), (200, 100))

        self.assertEqual(call("GET", "/users", victim)[0], 403)
        self.assertEqual(call("PATCH", f"/users/{victim_id}/status", admin, {"is_active": False})[0], 200)
        self.assertEqual(call("GET", "/auth/me", victim)[0], 401)
        self.assertEqual(call("GET", "/projects")[0], 401)


if __name__ == "__main__":
    unittest.main()
