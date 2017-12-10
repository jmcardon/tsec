object JWTMacExamples {

  import tsec.jwt._
  import tsec.jws.mac._
  import tsec.mac.imports._
  import scala.concurrent.duration._
  import cats.syntax.all._
  import cats.effect.Sync

  /** To create custom claims: */
  val claims = JWTClaims.build(expiration = Some(10.minutes))

  /** You can also chose to interpret into any target Monad with an instance of MonadError[F, Throwable] using JwtMacM */
  def jwtMonadic[F[_]: Sync]: F[JWTMac[HMACSHA256]] =
    for {
      key <- HMACSHA256.generateLift[F]
      jwt <- JWTMac.build[F, HMACSHA256](claims, key) //You can sign and build a jwt object directly
      verifiedFromObj <- JWTMac
        .verifyFromInstance[F, HMACSHA256](jwt, key) //You can verify the jwt straight from an object
      stringjwt  <- JWTMac.buildToString[F, HMACSHA256](claims, key)       //Or build it straight to string
      isverified <- JWTMac.verifyFromString[F, HMACSHA256](stringjwt, key) //You can verify straight from a string
      parsed     <- JWTMac.verifyAndParse[F, HMACSHA256](stringjwt, key)   //Or verify and return the actual instance
    } yield parsed

  /** Using impure either interpreters */
  val jwt: Either[Throwable, JWTMac[HMACSHA256]] = for {
    key <- HMACSHA256.generateKey()
    jwt <- JWTMacImpure.build[HMACSHA256](claims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMacImpure
      .verifyFromInstance[HMACSHA256](jwt, key) //You can verify the jwt straight from an object
    stringjwt  <- JWTMacImpure.buildToString[HMACSHA256](claims, key)       //Or build it straight to string
    isverified <- JWTMacImpure.verifyFromString[HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed     <- JWTMacImpure.verifyAndParse[HMACSHA256](stringjwt, key)   //Or verify and return the actual instance
  } yield parsed

}
