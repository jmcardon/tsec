package tsec.libsodium

import cats.effect.IO
import tsec.libsodium.kx._

class KeyExchangeTest extends SodiumSpec {

  behavior of "Sodium KeyExchange"

  it should "generate session KeyPair" in {

    val program: IO[SodiumKeyPair] = for {
      serverKeyPair <- KeyExchange.generateKeyPair[IO]
      clientKeyPair <- KeyExchange.generateKeyPair[IO]
      sessionKey    <- KeyExchange.generateClientSessionKeys[IO](serverKeyPair, clientKeyPair.pk)

    } yield sessionKey

    program.attempt.unsafeRunSync() mustBe a[Right[_, SodiumKeyPair]]
  }
//
//  it should "not generate session KeyPair providing wrong public key" in {
//    val program: IO[SodiumKeyPair] = for {
//      serverKeyPair <- KeyExchange.generateKeyPair[IO]
//      clientKeyPair <- KeyExchange.generateKeyPair[IO]
//      serverSessionKey <- KeyExchange.generateServerSessionKeys[IO](serverKeyPair, clientKeyPair.pk)
//      clientSessionKey <- KeyExchange.generateClientSessionKeys[IO](clientKeyPair, serverKeyPair.pk)
//
//    } yield sessionKey
//
//    program.attempt.unsafeRunSync() mustBe a[Left[Exception, _]]
//  }

}
