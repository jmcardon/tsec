package http4sExamples

import cats.Id

object csrfExample {
  import cats.effect.IO
  import org.http4s._
  import org.http4s.dsl.io._
  import tsec.csrf.TSecCSRF
  import tsec.mac.jca._

  val newKey   = HMACSHA256.generateKey[Id]
  val tsecCSRF = TSecCSRF[IO, HMACSHA256](newKey)

  val dummyService: HttpRoutes[IO] = tsecCSRF.withNewToken(HttpRoutes.of[IO] {
    case GET -> Root =>
      Ok()
  }) // This endpoint now provides a user with a new csrf token.

  val dummyService2: HttpRoutes[IO] = tsecCSRF.validate()(HttpRoutes.of[IO] {
    case GET -> Root / "hi" =>
      Ok()
  }) //This endpoint is csrf checked
}
