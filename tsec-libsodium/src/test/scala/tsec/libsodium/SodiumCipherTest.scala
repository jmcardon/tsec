package tsec.libsodium

import cats.effect.IO
import tsec.cipher.symmetric.core._
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.internal.SodiumCipherPlatform
import tsec.common._

class SodiumCipherTest extends SodiumSpec {

  final def testSecretBoxCipher[A](platform: SodiumCipherPlatform[A]): Unit = {
    behavior of s"${platform.algorithm} symmetric key"

    it should "generate key, encrypt and decrypt properly" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        val program = for {
          key     <- platform.generateKey[IO]
          encrypt <- platform.encrypt[IO](pt, key)
          decrypt <- platform.decrypt[IO](encrypt, key)
        } yield decrypt
        if (!s.isEmpty)
          program.unsafeRunSync().toHexString mustBe pt.toHexString
      }
    }

    it should "not decrypt properly for a wrong key" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key     <- platform.generateKey[IO]
            key2    <- platform.generateKey[IO]
            encrypt <- platform.encrypt[IO](pt, key)
            decrypt <- platform.decrypt[IO](encrypt, key2)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "encrypt and decrypt properly with a split tag" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key           <- platform.generateKey[IO]
            encryptedPair <- platform.encryptDetached[IO](pt, key)
            decrypt       <- platform.decryptDetached[IO](encryptedPair._1, key, encryptedPair._2)
          } yield decrypt).unsafeRunSync().toHexString mustBe pt.toHexString
      }
    }

    it should "not decrypt properly with an incorrect key detached" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key     <- platform.generateKey[IO]
            key2    <- platform.generateKey[IO]
            encrypt <- platform.encryptDetached[IO](pt, key)
            decrypt <- platform.decryptDetached[IO](encrypt._1, key2, encrypt._2)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "not decrypt properly with an incorrect tag but correct key" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key         <- platform.generateKey[IO]
            encrypt     <- platform.encryptDetached[IO](pt, key)
            randomBytes <- ScalaSodium.randomBytes[IO](platform.macLen)
            decrypt     <- platform.decryptDetached[IO](encrypt._1, key, AuthTag[A](randomBytes))
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }
  }

  testSecretBoxCipher(CryptoSecretBox)
  testSecretBoxCipher(XChacha20Poly1305)

}
