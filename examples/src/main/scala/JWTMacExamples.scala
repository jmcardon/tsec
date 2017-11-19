


object JWTMacExamples {

  import tsec.jwt._
  import tsec.jws.mac._
  import tsec.mac.imports._
  import scala.concurrent.duration._

  /** To create custom claims: */
  val claims = JWTClaims.build(expiration = Some(10.minutes))

  /** Using the default either interpreters */
  val jwt: Either[Throwable, JWTMac[HMACSHA256]] = for {
    key             <- HMACSHA256.generateKey()
    jwt             <- JWTMac.build[HMACSHA256](claims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMac.verifyFromInstance[HMACSHA256](jwt, key) //You can verify the jwt straight from an object
    stringjwt       <- JWTMac.buildToString[HMACSHA256](claims, key) //Or build it straight to string
    isverified      <- JWTMac.verifyFromString[HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed          <- JWTMac.verifyAndParse[HMACSHA256](stringjwt, key) //Or verify and return the actual instance
  } yield parsed

  import cats.syntax.all._
  import cats.effect.Sync

  /** You can also chose to interpret into any target Monad with an instance of MonadError[F, Throwable] using JwtMacM */
  def jwtMonadic[F[_]: Sync]: F[JWTMac[HMACSHA256]] = for {
    key <- HMACSHA256.generateLift[F]
    jwt <- JWTMacM.build[F, HMACSHA256](claims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMacM
      .verifyFromInstance[F, HMACSHA256](jwt, key) //You can verify the jwt straight from an object
    stringjwt  <- JWTMacM.buildToString[F, HMACSHA256](claims, key)       //Or build it straight to string
    isverified <- JWTMacM.verifyFromString[F, HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed     <- JWTMacM.verifyAndParse[F, HMACSHA256](stringjwt, key)   //Or verify and return the actual instance
  } yield parsed

}
