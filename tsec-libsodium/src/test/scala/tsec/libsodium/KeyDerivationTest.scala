package tsec.libsodium

import cats.data.StateT
import tsec.common._
import cats.effect.IO
import tsec.libsodium.kdf.KeyDerivation

class KeyDerivationTest extends SodiumSpec {

  behavior of "Key derivation"

  it should "generate multiple keys" in {

    val program = for {
      master <- KeyDerivation.generateKey[IO]
      context = "Examples"
      _ <- KeyDerivation.deriveKey[IO](master, 16, 1, context)
      _ <- KeyDerivation.deriveKey[IO](master, 32, 2, context)
      _ <- KeyDerivation.deriveKey[IO](master, 64, 3, context)
    } yield ()

    program.attempt.unsafeRunSync() mustBe a[Right[_, Unit]]
  }

  it should "fail generating derived key for invalid context length" in {
    forAll { (context: String) =>
      val ctx = context.utf8Bytes

      val program = for {
        master <- KeyDerivation.generateKey[IO]
        _      <- KeyDerivation.deriveKey[IO](master, 16, 1, context)
      } yield ()

      val result = program.attempt.unsafeRunSync()

      if (ctx.length != ScalaSodium.crypto_kdf_CONTEXTBYTES)
        result mustBe a[Left[Exception, _]]
      else
        result mustBe a[Right[_, Unit]]
    }
  }

  it should "fail generating derived key for invalid key length" in {
    forAll { (l: Int) =>
      val program = for {
        master <- KeyDerivation.generateKey[IO]
        context = "Examples"
        _ <- KeyDerivation.deriveKey[IO](master, l, 1, context)
      } yield ()

      val result = program.attempt.unsafeRunSync()

      if (ScalaSodium.crypto_kdf_BYTES_MIN <= l && ScalaSodium.crypto_kdf_BYTES_MAX >= l)
        result mustBe a[Right[_, Unit]]
      else
        result mustBe a[Left[Exception, _]]
    }
  }

}
