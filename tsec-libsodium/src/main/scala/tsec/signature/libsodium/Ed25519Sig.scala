package tsec.signature.libsodium

import cats.effect.Sync
import tsec.cipher.asymmetric.libsodium.SodiumSignatureError
import tsec.keygen.asymmetric.{AsymmetricKeyGen, AsymmetricKeyGenAPI}
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium._
import tsec.signature._

sealed trait Ed25519Sig

//Todo: Streaming sigs
object Ed25519Sig
    extends SignatureAPI[Ed25519Sig, PublicKey, PrivateKey]
    with AsymmetricKeyGenAPI[Ed25519Sig, PublicKey, PrivateKey, SodiumKeyPair] {

  val pubKLen  = ScalaSodium.crypto_sign_PUBLICKEYBYTES
  val privKLen = ScalaSodium.crypto_sign_SECRETKEYBYTES
  val sigLen   = ScalaSodium.crypto_sign_BYTES

  implicit def genSigner[F[_]](implicit F: Sync[F], S: ScalaSodium): Signer[F, Ed25519Sig, PublicKey, PrivateKey] =
    new Signer[F, Ed25519Sig, PublicKey, PrivateKey] {
      def sign(unsigned: Array[Byte], secretKey: PrivateKey[Ed25519Sig]): F[CryptoSignature[Ed25519Sig]] =
        F.delay(impl.sign(unsigned, secretKey))

      def verify(
          raw: Array[Byte],
          signature: CryptoSignature[Ed25519Sig],
          publicKey: PublicKey[Ed25519Sig]
      ): F[Boolean] =
        F.delay(impl.verify(raw, signature, publicKey))
    }

  implicit def keyGen[F[_]](
      implicit F: Sync[F],
      S: ScalaSodium
  ): AsymmetricKeyGen[F, Ed25519Sig, PublicKey, PrivateKey, SodiumKeyPair] =
    new AsymmetricKeyGen[F, Ed25519Sig, PublicKey, PrivateKey, SodiumKeyPair] {
      def generateKeyPair: F[SodiumKeyPair[Ed25519Sig]] =
        F.delay(impl.generateKeyPair)

      def buildPrivateKey(rawPk: Array[Byte]): F[PrivateKey[Ed25519Sig]] =
        F.delay(impl.buildPrivateKey(rawPk))

      def buildPublicKey(rawPk: Array[Byte]): F[PublicKey[Ed25519Sig]] =
        F.delay(impl.buildPublicKey(rawPk))
    }

  object impl {
    def generateKeyPair(implicit S: ScalaSodium): SodiumKeyPair[Ed25519Sig] = {
      val pubk  = PublicKey[Ed25519Sig](new Array[Byte](pubKLen))
      val privK = PrivateKey[Ed25519Sig](new Array[Byte](privKLen))
      S.crypto_sign_keypair(pubk, privK)
      SodiumKeyPair(pubk, privK)
    }

    def sign(
        unsigned: Array[Byte],
        secretKey: PrivateKey[Ed25519Sig]
    )(implicit S: ScalaSodium): CryptoSignature[Ed25519Sig] = {
      val out = new Array[Byte](sigLen)
      S.crypto_sign_detached(out, NullPtrInt, unsigned, unsigned.length, secretKey)
      CryptoSignature[Ed25519Sig](out)
    }

    def verify(
        raw: Array[Byte],
        signature: CryptoSignature[Ed25519Sig],
        publicKey: PublicKey[Ed25519Sig]
    )(implicit S: ScalaSodium): Boolean =
      S.crypto_sign_verify_detached(signature, raw, raw.length, publicKey) == 0

    def buildPrivateKey(rawPk: Array[Byte]): PrivateKey[Ed25519Sig] =
      if (rawPk.length != privKLen)
        throw SodiumSignatureError("Invalid Private Key")
      else
        PrivateKey[Ed25519Sig](rawPk)

    def buildPublicKey(rawPk: Array[Byte]): PublicKey[Ed25519Sig] =
      if (rawPk.length != pubKLen)
        throw SodiumSignatureError("Invalid Private Key")
      else
        PublicKey[Ed25519Sig](rawPk)
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
      throw SodiumSignatureError("Invalid message length")

    val out = RawMessage[Ed25519Sig](new Array[Byte](msgLen))
    if (S.crypto_sign_open(out, NullPtrInt, signedMessage, signedMessage.length, publicKey) != 0)
      throw SodiumSignatureError("Invalid Signature")
    RawMessage[Ed25519Sig](out)
  }
}
