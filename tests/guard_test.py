from datetime import datetime, timedelta
from falcon import testing
from falcon_jwt_guard import Guard

import unittest
import falcon
import json

class TestGuard(unittest.TestCase):

    def test_malformed_headers(self):
        app = falcon.App()
        auth = Guard("TEST")
        token = auth.generate_token()

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = json.dumps(req.context.claims)

        test = Test()

        app.add_route('/test', test)

        a = testing.simulate_get(app, '/test')
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"{token}"})
        c = testing.simulate_get(app, '/test', headers={"Authorization":f"Boss {token}"})

        # Force a decode exception (jwt.exceptions.InvalidTokenError)
        d = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer 43gfj30nc3fn340dfnehello!"})

        self.assertEqual(a.status_code, 401)
        self.assertEqual(b.status_code, 401)
        self.assertEqual(c.status_code, 401)
        self.assertEqual(d.status_code, 401)

    def test_expiration(self):
        app = falcon.App()
        auth = Guard("TEST")
        # Set Expiration to 24 hours ago
        token_a = auth.generate_token({"user": 7802}, expires=timedelta(hours=-24))

        # Expiration = None
        token_b = auth.generate_token({"user": 7802}, expires=None)

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = json.dumps(req.context.claims)

        test = Test()

        app.add_route('/test', test)
        # When using a token with a past expiration
        a = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_a}"})

        # When using a token with an unlimited (no expiration)
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_b}"})


        self.assertEqual(a.json, {"title": "401 Unauthorized", "description": "The provided token is expired."})
        self.assertEqual(b.status_code, 200)

    def test_leeway(self):
        app = falcon.App()
        auth = Guard("TEST", leeway=30)
        # leeway should make this work
        token_a = auth.generate_token({"user": 7802}, expires=timedelta(seconds=-30))
        # this should fail
        token_b = auth.generate_token({"user": 7802}, expires=timedelta(seconds=-31))

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = json.dumps(req.context.claims)

        test = Test()

        app.add_route('/test', test)
        # When using a token with an expiration date of 30 seconds past
        a = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_a}"})
        # When using a token with an expiration date of 31 seconds past
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_b}"})

        # now token a should fail too
        auth.leeway = 0
        c = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_a}"})

        # a
        self.assertIn("user", a.json)
        self.assertIn("exp", a.json)
        # b
        self.assertEqual(b.status_code, 401)
        # c
        self.assertEqual(c.status_code, 401)

    def test_token_options(self):
        app = falcon.App()
        auth = Guard("TEST", issuer="voltron")
        # Test general creation
        token_a = auth.generate_token({"user": 7802}, issued=True, starts=timedelta(seconds=-30))
        
        # Test if NBF blocks invalid tokens
        token_b = auth.generate_token({"user": 7802}, starts=timedelta(seconds=120))

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = json.dumps(req.context.claims)

        test = Test()

        app.add_route('/test', test)

        # Testing for presence of options
        a = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_a}"})

        # Testing that NBF causes an invalid token
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_b}"})

        # a
        self.assertIn("iss", a.json)
        self.assertEqual(a.json["iss"], "voltron")
        self.assertIn("nbf", a.json)
        self.assertIn("iat", a.json)

        # b
        self.assertEqual(b.status_code, 401)


if __name__ == '__main__':
    unittest.main()