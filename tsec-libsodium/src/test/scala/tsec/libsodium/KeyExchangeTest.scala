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
      serverSession <- KeyExchange.generateClientSessionKeys[IO](server, client.pk)

      clientKey <- CryptoSecretBox.buildKey[IO](clientSession.send)
      serverKey <- CryptoSecretBox.buildKey[IO](serverSession.receive)

      enc <- CryptoSecretBox.encrypt[IO](plainText, clientKey)
      dec <- CryptoSecretBox.decrypt[IO](enc, serverKey)
    } yield dec

    program.attempt.unsafeRunSync() mustBe a[Right[_, PlainText]]
  }

}
