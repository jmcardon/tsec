package tsec.libsodium

import cats.effect.IO
import tsec.cipher.symmetric.{AADEncryptor, _}
import tsec.common._
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.cipher.symmetric.libsodium._
import tsec.cipher.symmetric.libsodium.internal.SodiumAEADPlatform

class SodiumAEADTest extends SodiumSpec {

  final def testAEAD[A](p: SodiumAEADPlatform[A])(
      implicit E: AADEncryptor[IO, A, SodiumKey],
      kg: SymmetricKeyGen[IO, A, SodiumKey]
  ): Unit = {
    behavior of s"${p.algorithm} aead"
    implicit val ivGen = p.defaultIvGen[IO]

    it should "generate key, encrypt and decrypt properly" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encrypt[IO](pt, key)
          decrypt <- p.decrypt[IO](encrypt, key)
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
            key     <- p.generateKey[IO]
            key2    <- p.generateKey[IO]
            encrypt <- p.encrypt[IO](pt, key)
            decrypt <- p.decrypt[IO](encrypt, key2)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "generate key, encrypt and decrypt properly for aad" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = AAD(aad.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encryptWithAAD[IO](pt, key, saad)
          decrypt <- p.decryptWithAAD[IO](encrypt, key, saad)
        } yield decrypt
        program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly for a wrong key, but correct AAD" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = AAD(aad.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          key2    <- p.generateKey[IO]
          encrypt <- p.encryptWithAAD[IO](pt, key, saad)
          decrypt <- p.decryptWithAAD[IO](encrypt, key2, saad)
        } yield decrypt
        program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "only decrypt properly for the same aad" in {
      forAll { (s: String, aad: String, aad2: String) =>
        val pt    = PlainText(s.utf8Bytes)
        val saad  = AAD(aad.utf8Bytes)
        val saad2 = AAD(aad2.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encryptWithAAD[IO](pt, key, saad)
          decrypt <- p.decryptWithAAD[IO](encrypt, key, saad2)
        } yield decrypt
        if (aad != aad2)
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
        else
          program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "encrypt and decrypt properly with a split tag" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = AAD(aad.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key           <- p.generateKey[IO]
            encryptedPair <- p.encryptWithAADDetached[IO](pt, key, saad)
            decrypt       <- p.decryptWithAADDetached[IO](encryptedPair._1, key, saad, encryptedPair._2)
          } yield decrypt).unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly with an incorrect key detached" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = AAD(aad.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key     <- p.generateKey[IO]
            key2    <- p.generateKey[IO]
            encrypt <- p.encryptWithAADDetached[IO](pt, key, saad)
            decrypt <- p.decryptWithAADDetached[IO](encrypt._1, key2, saad, encrypt._2)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "only decrypt properly with an equal AAD" in {
      forAll { (s: String, aad: String, aad2: String) =>
        val pt    = PlainText(s.utf8Bytes)
        val saad  = AAD(aad.utf8Bytes)
        val saad2 = AAD(aad2.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          key2    <- p.generateKey[IO]
          encrypt <- p.encryptWithAADDetached[IO](pt, key, saad)
          decrypt <- p.decryptWithAADDetached[IO](encrypt._1, key2, saad, encrypt._2)
        } yield decrypt
        if (aad != aad2 || s.isEmpty || aad.isEmpty || aad2.isEmpty)
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
        else
          program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly with an incorrect tag but correct key" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = AAD(aad.utf8Bytes)
        val program = for {
          key         <- p.generateKey[IO]
          encrypt     <- p.encryptWithAADDetached[IO](pt, key, saad)
          randomBytes <- ScalaSodium.randomBytes[IO](p.authTagLen)
          decrypt     <- p.decryptWithAADDetached[IO](encrypt._1, key, saad, AuthTag[A](randomBytes))
        } yield decrypt
        program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

  }

  testAEAD(XChacha20AEAD)
  testAEAD(IETFChacha20)
  testAEAD(OriginalChacha20)
  testAEAD(AES256GCM)

}
