package tsec

import cats.effect.Sync
import jnr.ffi.LibraryLoader
import jnr.ffi.Platform
import jnr.ffi.annotations.In
import jnr.ffi.annotations.Out
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t
import jnr.ffi.types.size_t
import tsec.internal._

/** Libsodium bindings using jni-ffi.
  * Inspired from kalium's stuff.
  *
  */
sealed trait ScalaSodium
    extends Argon2
    with GenericHash
    with ShortHash
    with HmacSha256
    with HmacSha512
    with HmacSha512256
    with SCrypt
    with SecretBox
    with CryptoAEAD
    with OriginalChacha20Poly1305
    with Chacha20Poly1305IETF
    with XChacha20Poly1305IETF {

  def randombytes_buf(@Out buf: Array[Byte], @In @size_t size: Int): Unit

  /**
    * This function isn't thread safe. Be sure to call it once, and before
    * performing other operations.
    *
    * Check libsodium's documentation for more info.
    */
  def sodium_init: Int

  def sodium_version_string: String

}

object ScalaSodium
    extends Argon2Constants
    with GenericHashConstants
    with ShortHashConstants
    with HmacSha256Constants
    with HmacSha512Constants
    with HmacSha512256Constants
    with SCryptConstants
    with SecretBoxConstants
    with CryptoAEADConstants
    with OriginalChacha20Poly1305Constants
    with Chacha20Poly1305IETFConstants
    with XChacha20Poly1305IETFConstants {

  val MIN_SUPPORTED_VERSION: Array[Integer] = Array[Integer](1, 0, 3)

  private var versionSupported = false

  private def libraryName = Platform.getNativePlatform.getOS match {
    case Platform.OS.WINDOWS =>
      "libsodium"
    case _ =>
      "sodium"
  }

  private[tsec] lazy val Sodium: ScalaSodium = {
    val sodium = LibraryLoader
      .create(classOf[ScalaSodium])
      .search("/usr/local/lib")
      .search("/opt/local/lib")
      .search("lib")
      .load(libraryName)
    if (sodium.sodium_init < 0)
      throw new RuntimeException("ScalaSodium is not safe to use")
    sodium
  }

  def getSodiumUnsafe: ScalaSodium = Sodium

  def getSodium[F[_]](implicit F: Sync[F]): F[ScalaSodium] = F.delay(Sodium)

  def randomBytes[F[_]](len: Int)(implicit F: Sync[F], S: ScalaSodium): F[Array[Byte]] = F.delay {
    val bytes = new Array[Byte](len)
    S.randombytes_buf(bytes, len)
    bytes
  }

}
