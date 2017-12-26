package tsec.libsodium

import cats.effect.IO
import tsec.common._
import tsec.libsodium.pk.SignatureError
import tsec.libsodium.pk.signatures._

class PKSignaturesTest extends SodiumSpec {
  behavior of "Libsodium Signatures"

  it should "sign and verify for the same keypair" in {
    forAll { (s: String) =>
      val program = for {
        keyPair <- CryptoSig.generateKeyPair[IO]
        signed  <- CryptoSig.sign[IO](RawMessage(s.utf8Bytes), keyPair.privKey)
        verify  <- CryptoSig.verify[IO](RawMessage(s.utf8Bytes), signed, keyPair.pubKey)
      } yield verify

      program.unsafeRunSync() mustBe true
    }
  }

  it should "not sign and verify for the same keypair but wrong message" in {
    forAll { (s: String, s2: String) =>
      val program = for {
        keyPair <- CryptoSig.generateKeyPair[IO]
        signed  <- CryptoSig.sign[IO](RawMessage(s.utf8Bytes), keyPair.privKey)
        verify  <- CryptoSig.verify[IO](RawMessage(s2.utf8Bytes), signed, keyPair.pubKey)
      } yield verify
      program.unsafeRunSync() mustBe s == s2
    }
  }

  it should "not sign and verify for the same message but wrong key" in {
    forAll { (s: String) =>
      val program = for {
        keyPair  <- CryptoSig.generateKeyPair[IO]
        keyPair2 <- CryptoSig.generateKeyPair[IO]
        signed   <- CryptoSig.sign[IO](RawMessage(s.utf8Bytes), keyPair.privKey)
        verify   <- CryptoSig.verify[IO](RawMessage(s.utf8Bytes), signed, keyPair2.pubKey)
      } yield verify
      program.unsafeRunSync() mustBe false
    }
  }

  it should "sign and verify for the same keypair - combined" in {
    forAll { (s: String) =>
      val program = for {
        keyPair <- CryptoSig.generateKeyPair[IO]
        signed  <- CryptoSig.signCombined[IO](RawMessage(s.utf8Bytes), keyPair.privKey)
        verify  <- CryptoSig.verifyCombined[IO](signed, keyPair.pubKey)
      } yield verify.toUtf8String

      program.unsafeRunSync() mustBe s
    }
  }

  it should "not sign and verify for the same message but wrong key - combined" in {
    forAll { (s: String) =>
      val program = for {
        keyPair  <- CryptoSig.generateKeyPair[IO]
        keyPair2 <- CryptoSig.generateKeyPair[IO]
        signed   <- CryptoSig.signCombined[IO](RawMessage(s.utf8Bytes), keyPair.privKey)
        verify   <- CryptoSig.verifyCombined[IO](signed, keyPair2.pubKey)
      } yield verify
      program.attempt.unsafeRunSync() mustBe a[Left[SignatureError, _]]
    }
  }

}
