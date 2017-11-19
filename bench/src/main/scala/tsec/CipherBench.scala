package tsec

import java.util.concurrent.TimeUnit

import org.openjdk.jmh.annotations._
import cats.effect.IO
import tsec.cipher.symmetric._
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.imports.aead._
import tsec.libsodium._
import tsec.libsodium.cipher._
import tsec.common._
import tsec.libsodium.cipher.aead.AES256GCM

import scala.util.Random

@State(Scope.Thread)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class CipherBench {

  implicit lazy val sodium                    = ScalaSodium.getSodiumUnsafe
  lazy val chachaKey                          = XChacha20Poly1305.generateKeyUnsafe
  lazy val sodiumAESKey: SodiumKey[AES256GCM] = AES256GCM.generateKeyUnsafe
  lazy val jcaAESKey: SecretKey[AES256]       = AES256.generateKeyUnsafe()
  lazy val jcaAES                             = JCAAEADPure[IO, AES256, GCM, NoPadding]().unsafeRunSync()
  lazy val rand                               = new Random()
  lazy val longPlaintext                      = PlainText(Array.fill[Char](5000)(Random.nextInt(127).toChar).mkString.utf8Bytes)

  /** We test each io action
    * to view the related overhead, but we do not care about sequencing them
    *
    */
  @Benchmark
  def testJCA(): Unit =
    jcaAES
      .encrypt(longPlaintext, jcaAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumAES(): Unit =
    AES256GCM
      .encrypt[IO](longPlaintext, sodiumAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumXChacha20(): Unit =
    XChacha20Poly1305
      .encrypt[IO](longPlaintext, chachaKey)
      .unsafeRunSync()

}
