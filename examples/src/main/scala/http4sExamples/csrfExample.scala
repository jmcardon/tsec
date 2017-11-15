package http4sExamples

object csrfExample {
  import cats.effect.IO
  import tsec.mac.imports._
  import tsec.csrf.TSecCSRF
  import org.http4s._
  import org.http4s.dsl.io._

  val newKey = HMACSHA256.generateKeyUnsafe()
  val tsecCSRF = TSecCSRF[IO, HMACSHA256](newKey)

  val dummyService: HttpService[IO] = tsecCSRF.withNewToken(HttpService[IO] {
    case GET -> Root =>
      Ok()
  }) // This endpoint now provides a user with a new csrf token.

  val dummyService2: HttpService[IO] = tsecCSRF.validate()(HttpService[IO] {
    case GET -> Root / "hi" =>
      Ok()
  })//This endpoint is csrf checked
}
