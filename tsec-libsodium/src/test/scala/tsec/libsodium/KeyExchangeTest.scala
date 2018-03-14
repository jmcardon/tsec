package tsec.libsodium

import cats.effect.IO
import tsec.cipher.symmetric.libsodium.CryptoSecretBox
import tsec.cipher.symmetric._
import tsec.common._
import tsec.kx.libsodium._

class KeyExchangeTest extends SodiumSpec {

  behavior of "Sodium KeyExchange"

  implicit val strategy = CryptoSecretBox.defaultIvGen[IO]

  it should "encrypt and decrypt properly" in {
    forAll { (s: String) =>
      val plainText = PlainText(s.utf8Bytes)

      val program: IO[(PlainText, PlainText)] = for {
        server <- KeyExchange.generateKeyPair[IO]
        client <- KeyExchange.generateKeyPair[IO]

        clientSession <- KeyExchange.generateClientSessionKeys[IO](client, server.pubKey)
        serverSession <- KeyExchange.generateServerSessionKeys[IO](server, client.pubKey)

        // client to server
        clientKey1 <- CryptoSecretBox.buildKey[IO](clientSession.send)
        serverKey1 <- CryptoSecretBox.buildKey[IO](serverSession.receive)
        enc1       <- CryptoSecretBox.encrypt[IO](plainText, clientKey1)
        dec1       <- CryptoSecretBox.decrypt[IO](enc1, serverKey1)

        // server to client
        clientKey2 <- CryptoSecretBox.buildKey[IO](clientSession.receive)
        serverKey2 <- CryptoSecretBox.buildKey[IO](serverSession.send)
        enc2       <- CryptoSecretBox.encrypt[IO](dec1, serverKey2)
        dec2       <- CryptoSecretBox.decrypt[IO](enc2, clientKey2)

      } yield (dec1, dec2)

      val (dec1, dec2) = program.unsafeRunSync()

      dec1.toUtf8String mustBe dec2.toUtf8String
      dec1.toUtf8String mustBe plainText.toUtf8String
    }
  }

  it should "fail to decrypt with wrong client public key" in {
    forAll { (s: String) =>
      val plainText = PlainText(s.utf8Bytes)

      val program: IO[Unit] = for {
        server  <- KeyExchange.generateKeyPair[IO]
        client  <- KeyExchange.generateKeyPair[IO]
        client2 <- KeyExchange.generateKeyPair[IO]

        clientSession <- KeyExchange.generateClientSessionKeys[IO](client, server.pubKey)
        serverSession <- KeyExchange.generateServerSessionKeys[IO](server, client2.pubKey)

        // client to server
        clientKey <- CryptoSecretBox.buildKey[IO](clientSession.send)
        serverKey <- CryptoSecretBox.buildKey[IO](serverSession.receive)
        enc1      <- CryptoSecretBox.encrypt[IO](plainText, clientKey)
        _         <- CryptoSecretBox.decrypt[IO](enc1, serverKey)
      } yield ()

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

  it should "fail to decrypt with wrong server public key" in {
    forAll { (s: String) =>
      val plainText = PlainText(s.utf8Bytes)

      val program: IO[Unit] = for {
        server  <- KeyExchange.generateKeyPair[IO]
        server2 <- KeyExchange.generateKeyPair[IO]
        client  <- KeyExchange.generateKeyPair[IO]

        clientSession <- KeyExchange.generateClientSessionKeys[IO](client, server2.pubKey)
        serverSession <- KeyExchange.generateServerSessionKeys[IO](server, client.pubKey)

        // client to server
        clientKey <- CryptoSecretBox.buildKey[IO](clientSession.send)
        serverKey <- CryptoSecretBox.buildKey[IO](serverSession.receive)
        enc1      <- CryptoSecretBox.encrypt[IO](plainText, clientKey)
        _         <- CryptoSecretBox.decrypt[IO](enc1, serverKey)
      } yield ()

      program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
    }
  }

}
