package tsec.libsodium.pk.signatures

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium._
import tsec.libsodium.pk._

sealed trait CryptoSig

object CryptoSig {

  val pubKLen  = ScalaSodium.crypto_sign_PUBLICKEYBYTES
  val privKLen = ScalaSodium.crypto_sign_SECRETKEYBYTES
  val sigLen   = ScalaSodium.crypto_sign_BYTES

  def generateKeyPair[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair[CryptoSig]] = F.delay {
    val pubk  = PublicKey[CryptoSig](new Array[Byte](pubKLen))
    val privK = PrivateKey[CryptoSig](new Array[Byte](privKLen))
    S.crypto_sign_keypair(pubk, privK)
    SodiumKeyPair(pubk, privK)
  }

  def sign[F[_]](
      unsigned: RawMessage[CryptoSig],
      secretKey: PrivateKey[CryptoSig]
  )(implicit F: Sync[F], S: ScalaSodium): F[Signature[CryptoSig]] =
    F.delay {
      val out = new Array[Byte](sigLen)
      S.crypto_sign_detached(out, NullPtrInt, unsigned, unsigned.length, secretKey)
      Signature[CryptoSig](out)
    }

  def verify[F[_]](
      raw: RawMessage[CryptoSig],
      signature: Signature[CryptoSig],
      publicKey: PublicKey[CryptoSig]
  )(implicit F: Sync[F], S: ScalaSodium): F[Boolean] = F.delay {
    S.crypto_sign_verify_detached(signature, raw, raw.length, publicKey) == 0
  }

  def signCombined[F[_]](
      unsigned: RawMessage[CryptoSig],
      secretKey: PrivateKey[CryptoSig]
  )(implicit F: Sync[F], S: ScalaSodium): F[SignedMessage[CryptoSig]] =
    F.delay {
      val out = new Array[Byte](unsigned.length + sigLen)
      S.crypto_sign(out, NullPtrInt, unsigned, unsigned.length, secretKey)
      SignedMessage[CryptoSig](out)
    }

  def verifyCombined[F[_]](
      signedMessage: SignedMessage[CryptoSig],
      publicKey: PublicKey[CryptoSig]
  )(implicit F: Sync[F], S: ScalaSodium): F[RawMessage[CryptoSig]] = F.delay {
    val msgLen = signedMessage.length - sigLen
    if (msgLen < 0)
      throw SignatureError("Invalid message length")

    val out = RawMessage[CryptoSig](new Array[Byte](msgLen))
    if (S.crypto_sign_open(out, NullPtrInt, signedMessage, signedMessage.length, publicKey) != 0)
      throw SignatureError("Invalid Signature")
    RawMessage[CryptoSig](out)
  }
}
