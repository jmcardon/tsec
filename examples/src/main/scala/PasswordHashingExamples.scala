import cats.effect.IO
import tsec.passwordhashers.core.PasswordHash

object PasswordHashingExamples {

  import tsec.passwordhashers.imports._

  /** For password hashers, you have three options: BCrypt, SCrypt and HardenedScrypt
    * (Which is basically scrypt but with much more secure parameters, but a lot slower)
    */
  val bcryptHash: IO[PasswordHash[BCrypt]]                 = BCrypt.hashPassword[IO]("hiThere")
  val scryptHash: IO[PasswordHash[SCrypt]]                 = SCrypt.hashPassword[IO]("hiThere")
  val hardenedScryptHash: IO[PasswordHash[HardenedSCrypt]] = HardenedSCrypt.hashPassword[IO]("hiThere")

  /** To Validate, you can check against a hash! */
  val checkProgram: IO[Boolean] = for {
    hash  <- bcryptHash
    check <- BCrypt.check[IO]("hiThere", hash)
  } yield check

}
