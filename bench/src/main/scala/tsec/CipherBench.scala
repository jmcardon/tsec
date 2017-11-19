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

import scala.util.Random

@State(Scope.Thread)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class CipherBench {

  implicit lazy val sodium        = ScalaSodium.getSodiumUnsafe
  lazy val lsKey                  = XChacha20Poly1305.generateKeyUnsafe
  lazy val key: SecretKey[AES256] = AES256.generateKeyUnsafe()
  lazy val rand                   = new Random()
  lazy val longPlaintext          = PlainText(Array.fill[Char](5000)(Random.nextInt(127).toChar).mkString.utf8Bytes)
  lazy val jca                    = JCAAEADPure[IO, AES256, GCM, NoPadding]().unsafeRunSync()

  /** We test each io action
    * to view the related overhead, but we do not care about sequencing them
    *
    */
  @Benchmark
  def testJCA(): Unit =
    jca
      .encrypt(longPlaintext, key)
      .unsafeRunSync()

  @Benchmark
  def testLibSodium(): Unit =
    XChacha20Poly1305
      .encrypt[IO](longPlaintext, lsKey)
      .unsafeRunSync()

}
