package tsec.libsodium.cipher

import cats.effect.Sync
import tsec.cipher.symmetric
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.internal.SodiumCipherPlatform
import fs2._

sealed trait XChacha20Poly1305

object XChacha20Poly1305 extends SodiumCipherPlatform[XChacha20Poly1305] {
  val nonceLen: Int  = ScalaSodium.crypto_secretbox_xchacha20poly1305_NONCEBYTES
  val macLen: Int    = ScalaSodium.crypto_secretbox_xchacha20poly1305_MACBYTES
  val keyLength: Int = ScalaSodium.crypto_secretbox_xchacha20poly1305_KEYBYTES

  def algorithm: String = "XChacha20Poly1305"

  @inline private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20Poly1305]
  )(
      implicit S: ScalaSodium
  ): Int = S.crypto_secretbox_xchacha20poly1305_easy(cout, pt.content, pt.content.length, nonce, key)

  @inline private[tsec] def sodiumDecrypt(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20Poly1305],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_open_easy(origOut, ct.content, ct.content.length, ct.iv, key)

  @inline private[tsec] def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_detached(cout, tagOut, pt.content, pt.content.length, nonce, key)

  @inline private[tsec] def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20Poly1305],
      tagIn: AuthTag[XChacha20Poly1305],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_open_detached(origOut, ct.content, tagIn, ct.content.length, ct.iv, key)

  /** Encrypt a byte stream **/
  private def streamEncryption[F[_]: Sync](streamState: CryptoStreamState, key: SodiumKey[XChacha20Poly1305])(
      implicit S: ScalaSodium
  ): Pipe[F, Byte, Byte] = { in =>
    in.pull.unconsChunk.flatMap {
      case Some((chunk, stream)) =>
        goStream[F](chunk, stream, streamState, key)
      case None =>
        Pull.fail(new IllegalArgumentException("Cannot pull an empty stream")) //Todo: Better err type?
    }.stream
  }

  private def goStream[F[_]: Sync](
      lastChunk: Chunk[Byte],
      stream: Stream[F, Byte],
      state: CryptoStreamState,
      key: SodiumKey[XChacha20Poly1305]
  )(
      implicit S: ScalaSodium
  ): Pull[F, Byte, Unit] =
    stream.pull.unconsChunk.flatMap {
      case Some((c, str)) =>
        val inArray = lastChunk.toBytes.toArray
        Pull
          .output(Chunk.bytes(encryptStreamNotFinal(inArray, key, state)))
          .flatMap(_ => goStream[F](c, str, state, key))
      case None =>
        val inArray = lastChunk.toBytes.values
        Pull.output(Chunk.bytes(encryptStreamFinal(inArray, key, state)))
    }

  private def encryptStreamNotFinal(in: Array[Byte], key: SodiumKey[XChacha20Poly1305], state: CryptoStreamState)(
      implicit S: ScalaSodium
  ): Array[Byte] = {
    val outArray = new Array[Byte](in.length + ScalaSodium.crypto_secretstream_xchacha20poly1305_ABYTES)
    S.crypto_secretstream_xchacha20poly1305_push(
      state,
      outArray,
      ScalaSodium.NullPtrInt,
      in,
      in.length,
      ScalaSodium.NullPtrBytes,
      0,
      0
    )
    outArray
  }

  private def encryptStreamFinal(in: Array[Byte], key: SodiumKey[XChacha20Poly1305], state: CryptoStreamState)(
      implicit S: ScalaSodium
  ): Array[Byte] = {
    val outArray = new Array[Byte](in.length + ScalaSodium.crypto_secretstream_xchacha20poly1305_ABYTES)
    S.crypto_secretstream_xchacha20poly1305_push(
      state,
      outArray,
      ScalaSodium.NullPtrInt,
      in,
      in.length,
      ScalaSodium.NullPtrBytes,
      0,
      ScalaSodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    )
    outArray
  }

}
