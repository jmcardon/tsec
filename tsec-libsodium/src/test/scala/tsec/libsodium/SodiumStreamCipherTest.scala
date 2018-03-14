package tsec.libsodium

import cats.effect.IO
import fs2._
import tsec.common._
import tsec.cipher.symmetric.libsodium._

class SodiumStreamCipherTest extends SodiumSpec {

  // Test on a long string
  val testVector: Array[Byte] =
    """ Hello dear reader
      | Unfortunately, I want to test a long string
      | and I'm not original in making a funny message here
      | to test streaming.
      |
      | I sincerely apologize for how boring this may be.
      |
      | I'm watching MIBIII again as I write this,
      | It's pretty funny. Makes me kinda want a pug again.
    """.stripMargin.utf8Bytes

  behavior of "Streaming encryption and decryption"

  it should "Encrypt and decrypt properly" in {

    val program = for {
      key   <- XChacha20Poly1305.generateKey[IO]
      state <- XChacha20Poly1305.createEncryptionState[IO](key)
      original <- Stream
        .emits(testVector)
        .covary[IO]
        .through(XChacha20Poly1305.encryptionPipe[IO](state, 10))
        .through(XChacha20Poly1305.decryptionPipe[IO](state.header, key, 10))
        .compile
        .toVector
    } yield original.toArray

    program.unsafeRunSync().toHexString mustBe testVector.toHexString
  }

  it should "Not encrypt and decrypt for a wrong key but correct header" in {
    val program = for {
      key1  <- XChacha20Poly1305.generateKey[IO]
      key2  <- XChacha20Poly1305.generateKey[IO]
      state <- XChacha20Poly1305.createEncryptionState[IO](key1)
      original <- Stream
        .emits(testVector)
        .covary[IO]
        .through(XChacha20Poly1305.encryptionPipe[IO](state, 10))
        .through(XChacha20Poly1305.decryptionPipe[IO](state.header, key2, 10))
        .compile
        .toVector
    } yield original.toArray

    program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
  }

  it should "Not encrypt and decrypt for a wrong key and wrong header" in {
    val program = for {
      key1   <- XChacha20Poly1305.generateKey[IO]
      key2   <- XChacha20Poly1305.generateKey[IO]
      state1 <- XChacha20Poly1305.createEncryptionState[IO](key1)
      state2 <- XChacha20Poly1305.createEncryptionState[IO](key2)
      original <- Stream
        .emits(testVector)
        .covary[IO]
        .through(XChacha20Poly1305.encryptionPipe[IO](state1, 10))
        .through(XChacha20Poly1305.decryptionPipe[IO](state2.header, key2, 10))
        .compile
        .toVector
    } yield original.toArray

    program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
  }

}
