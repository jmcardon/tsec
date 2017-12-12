package tsec.libsodium.cipher

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.internal.SodiumCipherPlatform
import fs2._
import cats.syntax.all._

sealed trait XChacha20Poly1305

object XChacha20Poly1305 extends SodiumCipherPlatform[XChacha20Poly1305] {
  val nonceLen: Int  = ScalaSodium.crypto_secretbox_xchacha20poly1305_NONCEBYTES
  val macLen: Int    = ScalaSodium.crypto_secretbox_xchacha20poly1305_MACBYTES
  val keyLength: Int = ScalaSodium.crypto_secretbox_xchacha20poly1305_KEYBYTES

  /**Stream helpers **/
  private val ABytes                 = ScalaSodium.crypto_secretstream_xchacha20poly1305_ABYTES
  private val NonEmptyMinLen: Int    = ScalaSodium.crypto_secretstream_xchacha20poly1305_ABYTES + 1
  private val CompletionTag: Short   = ScalaSodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  private val StreamHeaderBytes: Int = ScalaSodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES

  private val GenericEncryptError = SodiumCipherError.StreamEncryptError("Could not encrypt successfully")
  private val GenericDecryptError = SodiumCipherError.StreamDecryptError("Could not decrypt successfully")

  final class CipherState(val header: CryptoStreamHeader, private[tsec] val state: CryptoStreamState)

  def algorithm: String = "XChacha20Poly1305"

  @inline private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20Poly1305]
  )(
      implicit S: ScalaSodium
  ): Int = S.crypto_secretbox_xchacha20poly1305_easy(cout, pt, pt.length, nonce, key)

  @inline private[tsec] def sodiumDecrypt(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20Poly1305],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_open_easy(origOut, ct.content, ct.content.length, ct.nonce, key)

  @inline private[tsec] def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_detached(cout, tagOut, pt, pt.length, nonce, key)

  @inline private[tsec] def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20Poly1305],
      tagIn: AuthTag[XChacha20Poly1305],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_open_detached(origOut, ct.content, tagIn, ct.content.length, ct.nonce, key)

  def decryptionPipe[F[_]](
      header: CryptoStreamHeader,
      key: SodiumKey[XChacha20Poly1305],
      chunkSize: Int
  )(implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte] = { in =>
    val initState = F.delay {
      val state = new Array[Byte](S.crypto_secretstream_xchacha20poly1305_statebytes)
      S.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
      CryptoStreamState(state)
    }
    Stream
      .eval(initState)
      .flatMap(st => streamDecryption[F](in, st, chunkSize))
  }

  private def streamDecryption[F[_]: Sync](
      in: Stream[F, Byte],
      streamState: CryptoStreamState,
      chunkSize: Int
  )(implicit S: ScalaSodium): Stream[F, Byte] =
    in.pull
      .unconsLimit(chunkSize + ABytes)
      .flatMap {
        case Some((chunk, stream)) =>
          decryptPull[F](chunkSize + ABytes, chunk, stream, streamState)
        case None =>
          Pull.raiseError(SodiumCipherError.StreamDecryptError("Cannot Decrypt an empty stream")) //Todo: Better err type?
      }
      .stream

  /** Statefully transform our cipher stream.
    * The ciphertext must be _at minimum_ `ABYTES + 1` (so it should contain more than just the auth tag).
    * If it is not, fail the stream.
    *
    * If the final chunk does not have a valid completion tag, fail the stream.
    */
  private def decryptPull[F[_]: Sync](
      chunkSize: Int,
      lastChunk: Segment[Byte, Unit],
      stream: Stream[F, Byte],
      state: CryptoStreamState,
  )(implicit S: ScalaSodium): Pull[F, Byte, Unit] =
    stream.pull.unconsLimit(chunkSize).flatMap {
      case Some((seg, str)) =>
        val cipherText = lastChunk.force.toArray
        if (cipherText.length < NonEmptyMinLen)
          Pull.raiseError(GenericDecryptError)
        else {
          Pull
            .eval(decryptSodiumStream[F](cipherText, state))
            .flatMap { ct =>
              Pull.outputChunk(Chunk.bytes(ct)) >> decryptPull[F](chunkSize, seg, str, state)
            }
        }
      case None =>
        val cipherText = lastChunk.force.toArray
        if (cipherText.length < NonEmptyMinLen)
          Pull.raiseError(GenericDecryptError)
        else {
          Pull
            .eval(decryptSodiumStreamWithTag[F](cipherText, state))
            .flatMap {
              case (ct, tag) =>
                if (tag != CompletionTag)
                  Pull.raiseError(GenericDecryptError)
                else
                  Pull.outputChunk(Chunk.bytes(ct)) >> Pull.done
            }
        }
    }

  def encryptionPipeAndHeader[F[_]](
      key: SodiumKey[XChacha20Poly1305],
      chunkSize: Int
  )(implicit F: Sync[F], S: ScalaSodium): F[(CryptoStreamHeader, Pipe[F, Byte, Byte])] =
    F.delay {
      val state  = new Array[Byte](S.crypto_secretstream_xchacha20poly1305_statebytes)
      val header = new Array[Byte](StreamHeaderBytes)
      S.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
      (CryptoStreamHeader(header), streamEncryption[F](CryptoStreamState(state), chunkSize))
    }

  def createEncryptionState[F[_]](
      key: SodiumKey[XChacha20Poly1305]
  )(implicit F: Sync[F], S: ScalaSodium): F[XChacha20Poly1305.CipherState] =
    F.delay {
      val header = new Array[Byte](StreamHeaderBytes)
      val state  = new Array[Byte](S.crypto_secretstream_xchacha20poly1305_statebytes)
      S.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
      new CipherState(CryptoStreamHeader(header), CryptoStreamState(state))
    }

  def encryptionPipe[F[_]](
      cipherState: XChacha20Poly1305.CipherState,
      chunkSize: Int
  )(implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte] =
    streamEncryption[F](cipherState.state, chunkSize)

  /** Encrypt a byte stream **/
  private def streamEncryption[F[_]: Sync](
      streamState: CryptoStreamState,
      chunkSize: Int
  )(implicit S: ScalaSodium): Pipe[F, Byte, Byte] = { in =>
    in.pull
      .unconsLimit(chunkSize)
      .flatMap {
        case Some((chunk, stream)) =>
          encryptPull[F](chunkSize, chunk, stream, streamState)
        case None =>
          Pull.raiseError(SodiumCipherError.StreamEncryptError("Cannot Encrypt an empty stream"))
      }
      .stream
  }

  /** Encrypt our stream in a `Pull`,
    * using the last chunk to keep track of the state of the stream
    */
  private def encryptPull[F[_]: Sync](
      chunkSize: Int,
      lastChunk: Segment[Byte, Unit],
      stream: Stream[F, Byte],
      state: CryptoStreamState
  )(
      implicit S: ScalaSodium
  ): Pull[F, Byte, Unit] =
    stream.pull.unconsLimit(chunkSize).flatMap {
      case Some((c, str)) =>
        val inArray = lastChunk.force.toArray
        Pull
          .eval(encryptSodiumStream(inArray, state))
          .flatMap(ct => Pull.outputChunk(Chunk.bytes(ct)) >> encryptPull[F](chunkSize, c, str, state))
      case None =>
        val inArray = lastChunk.force.toArray
        Pull
          .eval(encryptStreamFinal(inArray, state))
          .flatMap(ct => Pull.outputChunk(Chunk.bytes(ct)) >> Pull.done)
    }

  /** Encrypt the in array using the crypto stream state **/
  private def encryptSodiumStream[F[_]](in: Array[Byte], state: CryptoStreamState)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Array[Byte]] = F.delay {
    val outArray = new Array[Byte](in.length + ABytes)
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

  /** Encrypt the in array as the final chunk using the crypto stream state **/
  private def encryptStreamFinal[F[_]](in: Array[Byte], state: CryptoStreamState)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Array[Byte]] = F.delay {
    val outArray = new Array[Byte](in.length + ABytes)
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

  /** Run streaming decryption, but for an intermediate step: We _don't care_ about the tag **/
  def decryptSodiumStream[F[_]](in: Array[Byte], state: CryptoStreamState)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Array[Byte]] = F.delay {
    val outArray = new Array[Byte](in.length - ABytes)
    val outState = S.crypto_secretstream_xchacha20poly1305_pull(
      state,
      outArray,
      ScalaSodium.NullPtrInt,
      new Array[Byte](1), //Tag, but we don't care about the result, so we'll let the gc take care of it.
      in,
      in.length,
      ScalaSodium.NullPtrBytes,
      0
    )
    if (outState != 0)
      throw GenericDecryptError
    else
      outArray
  }

  def decryptSodiumStreamWithTag[F[_]](in: Array[Byte], state: CryptoStreamState)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(Array[Byte], Short)] = F.delay {
    val outArray = new Array[Byte](in.length - ABytes)
    val tag      = new Array[Byte](1)
    val outState = S.crypto_secretstream_xchacha20poly1305_pull(
      state,
      outArray,
      ScalaSodium.NullPtrInt,
      tag,
      in,
      in.length,
      ScalaSodium.NullPtrBytes,
      0
    )
    if (outState != 0)
      throw GenericDecryptError
    else
      (outArray, tag.head.toShort)
  }

}
