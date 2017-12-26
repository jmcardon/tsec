package tsec.authentication

import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.{Authorization => H4SA}
import tsec.common.SecureRandomId
import tsec.jws.mac.JWTMac
import tsec.mac.imports.HMACSHA256

import cats.effect.IO
import cats.implicits._

class TSecAuthServiceSpec extends AuthenticatorSpec {

  behavior of "Composability of TSecAuthService"

    it should "compile when combined via SemigroupK" in {

      val service: TSecAuthService[Authenticator[Int], DummyUser, IO] =
        TSecAuthService {
          case GET -> Root / "one" asAuthed _ => Ok()
        }

      val serviceTwo: TSecAuthService[Authenticator[Int], DummyUser, IO] =
        TSecAuthService {
          case GET -> Root / "two" asAuthed _ => Ok()
        }

      service <+> serviceTwo
    }

}
