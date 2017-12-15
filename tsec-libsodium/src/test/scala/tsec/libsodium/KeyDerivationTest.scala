package tsec.libsodium

import cats.data.StateT
import tsec.common._
import cats.effect.IO
import tsec.libsodium.kdf.KeyDerivation

class KeyDerivationTest extends SodiumSpec {

  behavior of "Key derivation"

  it should "generate multiple keys" in {

    val program = for {
      master <- StateT.lift(KeyDerivation.generateKey[IO])
      context = "Examples".utf8Bytes
      key1 <- KeyDerivation.deriveKey[IO](master, 16, context)
      key2 <- KeyDerivation.deriveKey[IO](master, 32, context)
      key3 <- KeyDerivation.deriveKey[IO](master, 64, context)
    } yield ()

    program.runA(1).attempt.unsafeRunSync() mustBe a[Right[_, Unit]]
  }

  it should "fail generating derived key for invalid context length" in {
    forAll { (s: String) =>
      val program = for {
        master <- StateT.lift(KeyDerivation.generateKey[IO])
        context = s.utf8Bytes
        key1 <- KeyDerivation.deriveKey[IO](master, 16, context)
      } yield ()

      val result = program.runA(1).attempt.unsafeRunSync()

      if (s.length != ScalaSodium.crypto_kdf_CONTEXTBYTES)
        result mustBe a[Left[Exception, _]]
      else
        result mustBe a[Right[_, Unit]]
    }
  }

  it should "fail generating derived key for invalid key length" in {
    forAll { (l: Int) =>
      val program = for {
        master <- StateT.lift(KeyDerivation.generateKey[IO])
        context = "Examples".utf8Bytes
        key1 <- KeyDerivation.deriveKey[IO](master, l, context)
      } yield ()

      val result = program.runA(1).attempt.unsafeRunSync()

      if (ScalaSodium.crypto_kdf_BYTES_MIN <= l && ScalaSodium.crypto_kdf_BYTES_MAX >= l)
        result mustBe a[Right[_, Unit]]
      else
        result mustBe a[Left[Exception, _]]
    }
  }

}
