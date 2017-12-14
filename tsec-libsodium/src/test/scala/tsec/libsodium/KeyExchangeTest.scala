package tsec.libsodium

import cats.effect.IO
import tsec.libsodium.cipher.{CryptoSecretBox, PlainText}
import tsec.libsodium.kx._
import tsec.common._

class KeyExchangeTest extends SodiumSpec {

  behavior of "Sodium KeyExchange"

  it should "generate session KeyPair" in {

    val plainText = PlainText("abcdef".utf8Bytes)

    val program: IO[PlainText] = for {
      server <- KeyExchange.generateKeyPair[IO]
      client <- KeyExchange.generateKeyPair[IO]

      clientSession <- KeyExchange.generateClientSessionKeys[IO](client, server.pk)
      serverSession <- KeyExchange.generateServerSessionKeys[IO](server, client.pk)

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
    } yield dec2

    program.unsafeRunSync() mustBe plainText
  }

}
