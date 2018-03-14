package tsec.libsodium

import cats.effect.IO
import tsec.cipher.symmetric._
import tsec.common._
import tsec.cipher.asymmetric.libsodium._

class PKEncryptionTest extends SodiumSpec {

  behavior of "Sodium Public Key Encryption"

  it should "encrypt and decrypt properly - normal" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        encrypt     <- CryptoBox.encrypt[IO](PlainText(s.utf8Bytes), recipientKP.pubKey, senderKP.privKey)
        decrypt     <- CryptoBox.decrypt[IO](encrypt, senderKP.pubKey, recipientKP.privKey)
      } yield decrypt.toUtf8String
      program.unsafeRunSync() mustBe s
    }
  }

  it should "not encrypt and decrypt properly an improper keypair" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        wrongKP     <- CryptoBox.generateKeyPair[IO]
        encrypt     <- CryptoBox.encrypt[IO](PlainText(s.utf8Bytes), recipientKP.pubKey, senderKP.privKey)
        decrypt     <- CryptoBox.decrypt[IO](encrypt, senderKP.pubKey, wrongKP.privKey)
      } yield decrypt.toUtf8String

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

  it should "encrypt and decrypt properly - detached" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        encrypt     <- CryptoBox.encryptDetached[IO](PlainText(s.utf8Bytes), recipientKP.pubKey, senderKP.privKey)
        decrypt     <- CryptoBox.decryptDetached[IO](encrypt._1, encrypt._2, senderKP.pubKey, recipientKP.privKey)
      } yield decrypt.toUtf8String
      program.unsafeRunSync() mustBe s
    }
  }

  it should "not encrypt and decrypt properly an improper keypair - detached" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        wrongKP     <- CryptoBox.generateKeyPair[IO]
        encrypt     <- CryptoBox.encryptDetached[IO](PlainText(s.utf8Bytes), recipientKP.pubKey, senderKP.privKey)
        decrypt     <- CryptoBox.decryptDetached[IO](encrypt._1, encrypt._2, senderKP.pubKey, wrongKP.privKey)
      } yield decrypt.toUtf8String

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

  it should "encrypt and decrypt properly - precalc normal" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        precalcOut  <- CryptoBox.precalcSharedKey[IO](recipientKP.pubKey, senderKP.privKey)
        precalcIn   <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, recipientKP.privKey)
        encrypt     <- CryptoBox.encryptPrecalc[IO](PlainText(s.utf8Bytes), precalcOut)
        decrypt     <- CryptoBox.decryptPrecalc[IO](encrypt, precalcIn)
      } yield decrypt.toUtf8String
      program.unsafeRunSync() mustBe s
    }
  }

  it should "not encrypt and decrypt properly an improper keypair - precalc normal" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP     <- CryptoBox.generateKeyPair[IO]
        recipientKP  <- CryptoBox.generateKeyPair[IO]
        wrongKP      <- CryptoBox.generateKeyPair[IO]
        precalcOut   <- CryptoBox.precalcSharedKey[IO](recipientKP.pubKey, senderKP.privKey)
        precalcIn    <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, recipientKP.privKey)
        precalcWRONG <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, wrongKP.privKey)
        encrypt      <- CryptoBox.encryptPrecalc[IO](PlainText(s.utf8Bytes), precalcOut)
        decrypt      <- CryptoBox.decryptPrecalc[IO](encrypt, precalcWRONG)
      } yield decrypt.toUtf8String

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

  it should "encrypt and decrypt properly - precalc detached" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP    <- CryptoBox.generateKeyPair[IO]
        recipientKP <- CryptoBox.generateKeyPair[IO]
        precalcOut  <- CryptoBox.precalcSharedKey[IO](recipientKP.pubKey, senderKP.privKey)
        precalcIn   <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, recipientKP.privKey)
        encrypt     <- CryptoBox.encryptPrecalcDetached[IO](PlainText(s.utf8Bytes), precalcOut)
        decrypt     <- CryptoBox.decryptPrecalcDetached[IO](encrypt._1, encrypt._2, precalcIn)
      } yield decrypt.toUtf8String
      program.unsafeRunSync() mustBe s
    }
  }

  it should "not encrypt and decrypt properly an improper keypair - precalc detached" in {
    forAll { (s: String) =>
      val program: IO[String] = for {
        senderKP     <- CryptoBox.generateKeyPair[IO]
        recipientKP  <- CryptoBox.generateKeyPair[IO]
        wrongKP      <- CryptoBox.generateKeyPair[IO]
        precalcOut   <- CryptoBox.precalcSharedKey[IO](recipientKP.pubKey, senderKP.privKey)
        precalcIn    <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, recipientKP.privKey)
        precalcWRONG <- CryptoBox.precalcSharedKey[IO](senderKP.pubKey, wrongKP.privKey)
        encrypt      <- CryptoBox.encryptPrecalcDetached[IO](PlainText(s.utf8Bytes), precalcOut)
        decrypt      <- CryptoBox.decryptPrecalcDetached[IO](encrypt._1, encrypt._2, precalcWRONG)
      } yield decrypt.toUtf8String

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

}
