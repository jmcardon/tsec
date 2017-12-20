package tsec.libsodium

import cats.data.StateT
import tsec.common._
import cats.effect.IO
import org.scalacheck.Gen
import tsec.libsodium.kdf.KeyDerivation

class KeyDerivationTest extends SodiumSpec {

  behavior of "Key derivation"

  it should "generate different keys for different id's & context" in {
    val keyLengthGen = Gen.choose(ScalaSodium.crypto_kdf_BYTES_MIN, ScalaSodium.crypto_kdf_BYTES_MAX)
    val contextGen   = Gen.listOfN(ScalaSodium.crypto_kdf_CONTEXTBYTES, Gen.alphaChar).map(_.mkString)
    val master       = KeyDerivation.generateKey[IO].unsafeRunSync()

    forAll(keyLengthGen, contextGen) { (n: Int, context: String) =>
      val program = for {
        k1      <- KeyDerivation.deriveKey[IO](master, n, 1, context)
        k2      <- KeyDerivation.deriveKey[IO](master, n, 2, context)
        k3      <- KeyDerivation.deriveKey[IO](master, n, 3, context)
      } yield (k1, k2, k3)

      val result = program.unsafeRunSync()
      result._1 must not be (result._2)
      result._2 must not be (result._3)
    }
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
