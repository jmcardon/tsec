# oauth2-server for Scala [![Build Status](https://travis-ci.org/nulab/scala-oauth2-provider.svg?branch=master)](https://travis-ci.org/nulab/scala-oauth2-provider)

[The OAuth 2.0](http://tools.ietf.org/html/rfc6749) server-side implementation written in Scala.

This provides OAuth 2.0 server-side functionality and supporting function for [Play Framework](http://www.playframework.com/) and [Akka HTTP](http://akka.io/).

The idea of this library originally comes from [oauth2-server](https://github.com/yoichiro/oauth2-server) which is Java implementation of OAuth 2.0.

## Supported OAuth features

This library supports all grant types.

- Authorization Code Grant
- Resource Owner Password Credentials Grant
- Client Credentials Grant
- Implicit Grant

and an access token type called [Bearer](http://tools.ietf.org/html/rfc6750).

## How to use

### Implement `DataHandler`

### Instatiate `TokenEndpoint`

### AuthInfo

```DataHandler``` returns ```AuthInfo``` as authorized information.
```AuthInfo``` is made up of the following fields.

```scala
case class AuthInfo[User](
  user: User,
  clientId: Option[String],
  scope: Option[String],
  redirectUri: Option[String]
)
```

- user
  - ```user``` is authorized by DataHandler
- clientId
  - ```clientId``` which is sent from a client has been verified by ```DataHandler```
  - If your application requires client_id for client authentication, you can get ```clientId``` as below
    - ```val clientId = authInfo.clientId.getOrElse(throw new InvalidClient())```
- scope
  - inform the client of the scope of the access token issued
- redirectUri
  - This value must be enabled on authorization code grant
