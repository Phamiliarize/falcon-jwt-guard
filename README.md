# falcon-jwt-guard

`falcon-jwt-guard` is a package that implements authentication for [Falcon](https://github.com/falconry/falcon) resources down to the **HTTP request method**. It is light weight and offers a very simple API to create JWT tokens and check them on request.

## Why jwt-guard?

There's several packages for adding JWT authentication to a Falcon API, but they are either old and unmaintained or do too much, such as: being connected to an ORM, defining how you should handle permissions, and completely controlling login. falcon-jwt-guard doesn't do that because it is **authentication** not *authorization*. It enables you to:

- Encode tokens that identify users
- Decode & verify those tokens proving identity

with low learning cost through [**native "before hooks"**](https://falcon.readthedocs.io/en/stable/api/hooks.html#before-hooks) rather than the usual middleware implementation. Along with a "makes sense API", resource protection becomes intuitive and *fast*.

 jwt-guard is also flexible. You can even do things such as having multiple Guard instances to protect certain API with stricter settings, or even completely different tokens.

 ## Basic Usage

```
pip install falcon-jwt-guard
```

Instance a Guard object. After taking a secret, you can pass [several configuration options](https://github.com/Phamiliarize/falcon-jwt-guard/wiki/Full-API-Reference) via kwargs.

```
from falcon_jwt_guard import Guard

auth = Guard("secret")
```

However you choose to implement login, you can now use the `generate_token` method in order to generate tokens for users.

```
auth.generate_token({"user": 7802 })
```

To protect a resource, simply pass the Guard instance to a before hook. On successful Authentication, you can access the claims from `req.context.claims`.

```
@falcon.before(auth)
class Message:
    def on_post(self, req, resp, project_id):
        user = req.context.claims["user]

    def on_get(self, req, resp, project_id):
        user = req.context.claims["user]
```

If you want more macro-control, you can go by methods.


```
class Message:
    @falcon.before(auth)
    def on_post(self, req, resp, project_id):
        user = req.context.claims["user]

    def on_get(self, req, resp, project_id):
        pass
```

Depending on your usage pattern `auth` can be put instanced in a central file like "app" or "main" and exported out and used by other resources. You can also create multiple Guard instances, which might allow you to do things such as having tighter enforcements on areas like "billing" versus other areas of your API. Check out our [API documentation](https://github.com/Phamiliarize/falcon-jwt-guard/wiki/Full-API-Reference) for more details on how you can customize things.


## Call for Contributions

All contributions are always welcome. Being a security solution, the more the better. As this is a rather small package there's no system in place. Feel free to open a pull request!

We don't adopt any specific code of conduct but the general rule of thumb is don't be a jerk- golden rule it.

### Test Coverage

Contributions should check to ensure that coverage meets at minimum current main branch quality.

```
Name                           Stmts   Miss  Cover   Missing
------------------------------------------------------------
falcon_jwt_guard/__init__.py       1      0   100%
falcon_jwt_guard/guard.py         42      0   100%
------------------------------------------------------------
TOTAL                             43      0   100%
```
