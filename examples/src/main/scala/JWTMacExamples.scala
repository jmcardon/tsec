import java.time.Instant

object JWTMacExamples {

  import tsec.jwt._
  import tsec.jws.mac._
  import tsec.mac.imports._
  import scala.concurrent.duration._
  import cats.syntax.all._
  import cats.effect.Sync

  /** You can interpret into any target Monad with an instance of Sync[F] using JwtMac */
  def jwtMonadic[F[_]: Sync]: F[JWTMac[HMACSHA256]] =
    for {
      key    <- HMACSHA256.generateLift[F]
      claims <- JWTClaims.withDuration[F](expiration = Some(10.minutes))
      jwt    <- JWTMac.build[F, HMACSHA256](claims, key) //You can sign and build a jwt object directly
      verifiedFromObj <- JWTMac
        .verifyFromInstance[F, HMACSHA256](jwt, key) //You can verify the jwt straight from an object
      stringjwt  <- JWTMac.buildToString[F, HMACSHA256](claims, key)       //Or build it straight to string
      isverified <- JWTMac.verifyFromString[F, HMACSHA256](stringjwt, key) //You can verify straight from a string
      parsed     <- JWTMac.verifyAndParse[F, HMACSHA256](stringjwt, key)   //Or verify and return the actual instance
    } yield parsed

  /** Using impure either interpreters */
  val impureClaims = JWTClaims(expiration = Some(Instant.now.plusSeconds(10.minutes.toSeconds)))

  val jwt: Either[Throwable, JWTMac[HMACSHA256]] = for {
    key             <- HMACSHA256.generateKey()
    jwt             <- JWTMacImpure.build[HMACSHA256](impureClaims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMacImpure.verifyFromInstance[HMACSHA256](jwt, key)
    stringjwt       <- JWTMacImpure.buildToString[HMACSHA256](impureClaims, key) //Or build it straight to string
    isverified      <- JWTMacImpure.verifyFromString[HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed          <- JWTMacImpure.verifyAndParse[HMACSHA256](stringjwt, key) //Or verify and return the actual instance
  } yield parsed

}
