# Service Composition

### What we want to solve
Tsec provides ways to leverage Authentication, and Authorization to your endpoints. This means that for one route your could have endpoints with different authentication/Authorization mechanisms.

For instance, let's say we have an `item` route with three different endpoints having different security mechanisms :
```
GET /api/v1/items -> unauthenticated: everyone on the internet can get items.
PUT /api/v1/items -> authenticated: Only logged in users can create new items.
DELETE /api/v1/items -> authenticated and authorized: Only logged in admins can delete items.
```

So what we want to achieve is to expose these endpoints with Http4s within a single route. Let's do that.


### Preparation
I the following example we will use the BearerToken authentication mechanisms, which configuration can be found [here](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/http4sExamples/BearerTokenExample.scala)

BearerToken boilerplate:
```
// Create users
val adminUser: DummyUser = DummyUser(0, "admin", DummyRole.Admin)
val lambdaUser: DummyUser = DummyUser(1, "user", DummyRole.User)

// Store them
userStore.put(adminUser).unsafeRunSync()
userStore.put(lambdaUser).unsafeRunSync()

// Create bearer tokens
val adminToken = Auth.authenticator.create(adminUser.id).unsafeRunSync()
val userToken = Auth.authenticator.create(lambdaUser.id).unsafeRunSync()

//define Authorization policy
val rbacPolicy = BasicRBAC[IO, DummyRole, DummyUser, TSecBearerToken[Int]](DummyRole.Admin)
```

Now let's look at our endpoints definitions:
```
val deleteItem = Auth.liftService(TSecAuthService.withAuthorization(rbacPolicy) {
   case DELETE -> Root / "items" asAuthed adminUser => IO(Response(status = Status.NoContent))
})

val putItem = Auth.liftService(TSecAuthService {
   case PUT -> Root / "items" asAuthed user => IO(Response(status = Status.Created))
})

val getItem = HttpRoutes.of[IO] {
  case GET -> Root / "items" => IO(Response(status = Status.NoContent))
}
```
Let's expose them.
```
// Service composition
val securedService = deleteItem <+> putItem <+> getItem

val myApp = securedService.orNotFound
```
And finally let's test them
```
// Requests
val getReq = Request[IO](method = Method.GET, uri = Uri.uri("items"))

val putReq = Request[IO](method = Method.PUT, uri = Uri.uri("items"))
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))

val delReq = Request[IO](method = Method.DELETE, uri = Uri.uri("items"))
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, adminToken.id)))

// Endpoints Test
myApp.run(getReq).unsafeRunSync().status mustBe Status.Ok
myApp.run(putReq).unsafeRunSync().status mustBe Status.Created
myApp.run(delReq).unsafeRunSync().status mustBe Status.NoContent
```

_Running the test fails_:   
* The access to the `GET` endpoint is denied saying the user is not authorized with `HTTP 401`. Let's try to change the service composition order, putting the getItem service first ```val securedService = getItem <+> deleteItem <+> putItem ```. The `GET` succeeds, but now ...
* The `PUT` fails with a `HTTP 401`. Let's now change the service composition order to ```val securedService = getItem <+> putItem <+> deleteItem```. Now the test for the `PUT` endpoint is a success, but the test for the `DELETE` endpoint fails with `HTTP 404`

### Insights

From there we can make a *guess* about service composition behavior:
* unsecured services let requests pass through other services down the chain.
* services that requires authentication don't let requests pass through other services down the chain throwing a `HTTP 404`.
* services that bot requires authentication and Authorization don't let requests pass through other services down the chain throwing a `HTTP 401`.

Looking at the implementation of the `TSecAuthService` we can see that:
* A `TSecAuthService` can be seen as a function that applies the endpoint logic to the SecuredRequest.
* This function application can be constrained by an authorization mechanisms with the `withAuthorization` method. We can also provide a fallback if the authorization fails with the `withAuthorizationHandler` method.

And looking at the implementation of the `SecuredRequestHandler`:
* The `SecuredRequestHandler` lifts this a `TSecAuthService` into an `HttpRoute` through a `TSecMiddleware` that checks whether the user is authenticated or not.
* `SecuredRequestHandler` also provides a fall through mechanisms when the user is not authenticated.

Now let's try to leverage the fall-through mechanism at our disposal. We can see that `TSecAuthService.withAuthorizationHandler` accepts a function of type `SecuredRequest[F, I, A] => OptionT[F, Response[F]]`, which is basically a `TSecAuthService`! That's what we'll provide.

### Rework

We will first strip down our endpoint logic to PartialFunction and we will feed our services with them.
```
type PartialEndpoint[F[_]] = PartialFunction[SecuredRequest[IO, DummyUser, TSecBearerToken[Int]], IO[Response[IO]]]

val deleteItem: PartialEndpoint[F] = {
   case DELETE -> Root / "items" asAuthed _ => IO(Response(status = Status.NoContent))
 }

 val putItem: PartialEndpoint[F] = {
   case PUT -> Root / "items" asAuthed _ => IO(Response(status = Status.Created))
 }

//left intact
 val getItem = HttpRoutes.of[IO] {
   case GET -> Root / "items" => IO(Response(status = Status.Ok))
 }
```

And now we can now create and compose our services in order for our three requests to succeed. We first put the unauthenticated endpoint, so unauthenticated users can reach it. Then we combine it with our second service. This second service will first, service authorized users, and then (if user is not authorized, or endpoint not found) fall through an authenticated service.  

```
 val securedService = getItem <+> Auth
 .liftService(TSecAuthService.withAuthorizationHandler(rbacPolicy)(deleteItem, TSecAuthService(putItem).run))
```

If we run the tests, then you should see your three requests pass.

### And finally

We can now re-write our three assumptions defined earlier and use those as rule of thumbs when coding:
* unsecured services let requests pass through other services down the chain.
* services that requires authentication, have a fallthrough mechanism is case of failed authentication.
* services that bot requires authentication and Authorization, have a fall-through mechanism when authenticated users authorization fails.


### Going further:
We're nearly done. Let's just check if an unauthenticated user can access endpoints that require authentication/authorization and if an unauthorized user can access authorized endpoints.

```
val putReqUnAuth = Request[IO](method = Method.PUT, uri = Uri.uri("items"))
val delReqUnAuth = Request[IO](method = Method.DELETE, uri = Uri.uri("items"))

myApp.run(putReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized
myApp.run(delReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized

val delReqUnauth2 = Request[IO](method = Method.DELETE, uri = Uri.uri("items"))
  .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))
myApp.run(delReqUnauth2).unsafeRunSync().status mustBe Status.NotFound
```
The tests pass, but here we can see that we are leaking the fact that admin endpoints do exist for unauthenticated users (second statement). A best practice is to hide the face that admin endpoints do exist as described [here](https://developer.github.com/v3/troubleshooting/#why-am-i-getting-a-404-error-on-a-repository-that-exists).


Let's try to code a combination that does the trick:
```
val securedService = getItem <+> Auth.liftWithFallthrough(
   TSecAuthService(putItem),
   Auth.liftService(TSecAuthService.withAuthorization(rbacPolicy)(deleteItem)).orNotFound.run)
```
In this case though, you will never reach the `deleteItem` endpoint. This is because the fall through mechanism will be active in case of failed authentication only. Here our authentication is successful, but the endpoint is not found in the `TSecAuthService(putItem)` service, hence `HTTP 404`. So the following composition `unauthenticated <+> authenticated <+> authorized` cannot be achieved. There is a little room for improvement.
