---
layout: docs
number: 10
title: "Authorization"
---

# Authorization

TSec provides an authorization trait that can be plugged into a `SecuredRequestHandler`, extended for custom logic,
composed, extended or run manually over your request and flatmapped.

Let's look at the signature for Authorization

```scala
trait Authorization[F[_], Identity, Auth] {
  def isAuthorized(toAuth: SecuredRequest[F, Identity, Auth]): OptionT[F, SecuredRequest[F, Identity, Auth]]
}
```

That is: An effect type, an identity type (i.e your user type) and an authenticator (your token type). 
In essence, this allows you to perform authorization actions based on the type of secured request you have, and extend custom
logic if you need to, to do complicated actions such as caching tokens for an endpoint where authorization may be expensive.

Authorizations compose. After all, we can model it as a monoid (and we also provide a monoid instance for authorization)
 as such:
 
```scala
object Authorization {
  implicit def authorizationMonoid[F[_]: Monad, I, Auth]: Monoid[Authorization[F, I, Auth]] =
    new Monoid[Authorization[F, I, Auth]] {
      def empty: Authorization[F, I, Auth] = new Authorization[F, I, Auth] {

        def isAuthorized(toAuth: SecuredRequest[F, I, Auth]): OptionT[F, SecuredRequest[F, I, Auth]] =
          OptionT.pure(toAuth)
      }

      def combine(x: Authorization[F, I, Auth], y: Authorization[F, I, Auth]): Authorization[F, I, Auth] =
        new Authorization[F, I, Auth] {
          def isAuthorized(toAuth: SecuredRequest[F, I, Auth]): OptionT[F, SecuredRequest[F, I, Auth]] =
            x.isAuthorized(toAuth).flatMap(y.isAuthorized)
        }
    }
}
``` 

That is, our monoid empty is simply `pure` over the request.

For multiple authorizations, you could also compose manually instead of a monoid, which will create a new object
per n authorizations, by simply chaining flatmaps.

### Note:

Authenticators tend to rely on `SimpleAuthEnum`, which requires its representation type to be a primitive `Byte, Long or Int`,
or a `String`

## Built-in instances

TSec provides a few built in instances for authorization common use cases.

## Role-based authentication.

We provide two traits for [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control): BasicRBAC and DynamicRBAC.

Both require an instance of `AuthorizationInfo[F, Role, U]`, where `Role` is your enum of roles that you have 
(i.e Admin, User, Staff) and U is your user type. They also rely on an `AuthGroup`, which is a newtype over an `Array[A]`
which we provide helpers to construct. It's essentially to construct an array like a set, for faster indexing (sets are slow as hell!)

The main difference between `BasicRBAC` and `DynamicRBAC` is that BasicRBAC is for endpoints whose authorized roles
will never change (i.e always an admin endpoint), whereas Dynamic is for groups that may change over time, thus
it requires an instance of `trait DynamicAuthGroup[F[_], Role]`

BasicRBAC provides a helper `.all`, which will let _all_ roles pass through, and an apply method which takes
the allowed roles, i.e, from our tests:


```scala
  val basicRBAC = BasicRBAC[IO, DummyRole, AuthDummyUser, Int](DummyRole.Admin, DummyRole.Other) //Where DummyRole is some auth role
```


## Discretionary access control

We provide one `BasicDAC` class that implements the idea of discretionary access control:

```scala
abstract class BasicDAC[F[_], G, U, Auth](implicit eq: Eq[G], F: MonadError[F, Throwable])
    extends Authorization[F, U, Auth] {
  def fetchGroup: F[AuthGroup[G]]

  def fetchOwner: F[G]

  def fetchAccess(u: SecuredRequest[F, U, Auth]): F[G]
  //...
```

Wherein you have to implement fetchGroup and fetchOwner for a resource or particular request. i.e, from our tests:

```scala
 val basicDAC = new BasicDAC[IO, Int, AuthDummyUser, Int] {
    def fetchGroup: IO[AuthGroup[Int]] = IO.pure(AuthGroup(4, 5, 6))

    def fetchOwner: IO[Int] = IO.pure(1)

    def fetchAccess(u: SecuredRequest[IO, AuthDummyUser, Int]): IO[Int] = IO.pure(u.identity.id)
  }
```

## Hierarchy-based access control

Similar to say, the linux kernel, wherein you have roles that could be numerically represented in a hierarchy,
we have a `HierarchyAuth` class.

Note:
* The highest allowed auth level is 0, like the linux kernel.
* Higher authorization means smaller in number
* Your authorization enum must be numerical.

As an example, an auth enum could be:

```scala
sealed case class AuthLevel(i: Int)
object AuthLevel extends SimpleAuthEnum[AuthLevel, Int] {
  implicit object CEO           extends AuthLevel(0) //Implicit obj to get over SI-7046 which still pops up sometimes
  implicit object Staff         extends AuthLevel(1)
  implicit object AugmentedUser extends AuthLevel(2)
  implicit object RegularUser   extends AuthLevel(3)
  implicit object Err           extends AuthLevel(-1)

  val getRepr: (AuthLevel) => Int            = _.i
  protected val values: AuthGroup[AuthLevel] = AuthGroup(CEO, Staff, AugmentedUser, RegularUser)
  val orElse: AuthLevel                      = Err
}
```

Wherein our highest authorized role is `CEO`, then you can create an authorization like:

```scala
  val hierarchyAuth: IO[HierarchyAuth[F, AuthLevel, MyUserType, JWTMac[A]]] = 
    HierarchyAuth[IO, AuthLevel, MyUserType, JWTMac[A]](AuthLevel.Staff) 
```

Hierarchy based authorization will let any higher or equal authorization pass, and deny all the rest,
thus, in our example, using `AuthLevel.Staff` (aka 1), this authorization allows either `CEO` or `Staff` to use
this endpoint. 

## Bell-LaPadula

As a final built-in enum, we offer the classic, [Bell-LaPadula](https://en.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model)
authorization model. we have two things that concern us, reading, and writing, thus we have:

```scala
sealed abstract case class BLPReadAction[F[_], Role, A, Auth](authLevel: Role)(
    implicit authInfo: AuthorizationInfo[F, Role, A],
    enum: SimpleAuthEnum[Role, Int],
    F: MonadError[F, Throwable]
)
sealed abstract case class BLPWriteAction[F[_], Role, A, Auth](authLevel: Role)(
    implicit authInfo: AuthorizationInfo[F, Role, A],
    enum: SimpleAuthEnum[Role, Int],
    F: MonadError[F, Throwable]
) 
```

Similar to hierarchy-based auth, except that there is no reading to a higher authorization level (i.e lower in number),
and no writing to any auth level but your own (strong star property).