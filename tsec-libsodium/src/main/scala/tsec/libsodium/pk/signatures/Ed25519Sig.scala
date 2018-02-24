package tsec.libsodium.pk.signatures

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium._
import tsec.libsodium.pk._
import tsec.signature.core.CryptoSignature

sealed trait Ed25519Sig

//Todo: Streaming sigs
object Ed25519Sig {

  val pubKLen  = ScalaSodium.crypto_sign_PUBLICKEYBYTES
  val privKLen = ScalaSodium.crypto_sign_SECRETKEYBYTES
  val sigLen   = ScalaSodium.crypto_sign_BYTES

  def generateKeyPair[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair[Ed25519Sig]] = F.delay {
    val pubk  = PublicKey[Ed25519Sig](new Array[Byte](pubKLen))
    val privK = PrivateKey[Ed25519Sig](new Array[Byte](privKLen))
    S.crypto_sign_keypair(pubk, privK)
    SodiumKeyPair(pubk, privK)
  }

  def sign[F[_]](
      unsigned: RawMessage[Ed25519Sig],
      secretKey: PrivateKey[Ed25519Sig]
  )(implicit F: Sync[F], S: ScalaSodium): F[CryptoSignature[Ed25519Sig]] =
    F.delay {
      val out = new Array[Byte](sigLen)
      S.crypto_sign_detached(out, NullPtrInt, unsigned, unsigned.length, secretKey)
      CryptoSignature[Ed25519Sig](out)
    }

  def verify[F[_]](
      raw: RawMessage[Ed25519Sig],
      signature: CryptoSignature[Ed25519Sig],
      publicKey: PublicKey[Ed25519Sig]
  )(implicit F: Sync[F], S: ScalaSodium): F[Boolean] = F.delay {
    S.crypto_sign_verify_detached(signature, raw, raw.length, publicKey) == 0
  }

  def signCombined[F[_]](
      unsigned: RawMessage[Ed25519Sig],
      secretKey: PrivateKey[Ed25519Sig]
  )(implicit F: Sync[F], S: ScalaSodium): F[SignedMessage[Ed25519Sig]] =
    F.delay {
      val out = new Array[Byte](unsigned.length + sigLen)
      S.crypto_sign(out, NullPtrInt, unsigned, unsigned.length, secretKey)
      SignedMessage[Ed25519Sig](out)
    }

  def verifyCombined[F[_]](
      signedMessage: SignedMessage[Ed25519Sig],
      publicKey: PublicKey[Ed25519Sig]
  )(implicit F: Sync[F], S: ScalaSodium): F[RawMessage[Ed25519Sig]] = F.delay {
    val msgLen = signedMessage.length - sigLen
    if (msgLen < 0)
      throw SignatureError("Invalid message length")

    val out = RawMessage[Ed25519Sig](new Array[Byte](msgLen))
    if (S.crypto_sign_open(out, NullPtrInt, signedMessage, signedMessage.length, publicKey) != 0)
      throw SignatureError("Invalid Signature")
    RawMessage[Ed25519Sig](out)
  }
}
