from falcon import testing
from jwt_guard import Guard

import unittest
import falcon
from datetime import datetime, timedelta, closed_wsgi_iterable

class TestGuard(unittest.TestCase):

    def test_malformed_headers(self):
        app = falcon.App()
        auth = Guard("TEST")
        token = auth.generate_token()

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = req.context.claims

        test = Test()

        app.add_route('/test', test)

        a = testing.simulate_get(app, '/test')
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"{token}"})
        c = testing.simulate_get(app, '/test', headers={"Authorization":f"Boss {token}"})

        self.assertEqual(a.status_code, 401)
        self.assertEqual(b.status_code, 401)
        self.assertEqual(c.status_code, 401)

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
                resp.text = req.context.claims

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
        token_a = auth.generate_token({"user": 7802}, expires=timedelta(seconds=-30))
        token_b = auth.generate_token({"user": 7802}, expires=timedelta(seconds=-28))

        @falcon.before(auth)
        class Test:
            def on_get(self, req, resp):
                resp.text = req.context.claims

        test = Test()

        app.add_route('/test', test)
        # When using a token with an expiration date of 32 seconds past
        a = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_a}"})
        # When using a token with an expiration date of 28 seconds past
        b = testing.simulate_get(app, '/test', headers={"Authorization":f"Bearer {token_b}"})

        # self.assertIn(user in a.json and exp in a.json)
        # self.assertEqual(b.status_code, 200)

if __name__ == '__main__':
    unittest.main()