package tsec.jwt.util

import java.security.KeyFactory
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}

import cats.MonadError
import tsec.signature.core.SigAlgoTag
import tsec.signature.imports._

object ParseEncodedKeySpec {

  def pubKeyFromBytes[A: SigAlgoTag](keyBytes: Array[Byte])(implicit kt: KFTag[A]): SigPublicKey[A] = {
    val spec = new X509EncodedKeySpec(keyBytes)
    SigPublicKey[A](
      KeyFactory
        .getInstance(kt.keyFactoryAlgo, "BC")
        .generatePublic(spec)
    )
  }

  def privKeyFromBytes[A: SigAlgoTag](keyBytes: Array[Byte])(implicit kt: KFTag[A]): SigPrivateKey[A] = {
    val spec = new PKCS8EncodedKeySpec(keyBytes)
    SigPrivateKey[A](
      KeyFactory
        .getInstance(kt.keyFactoryAlgo, "BC")
        .generatePrivate(spec)
    )
  }

  /**
    * ASN.1/DER to the concat required by https://tools.ietf.org/html/rfc7518#section-3.4
    * Adapted from scala-jwt, itself adapted from jose4j
    */
  def derToConcat[F[_], A](
      derSignature: Array[Byte]
  )(implicit ecTag: ECKFTag[A], me: MonadError[F, Throwable]): F[Array[Byte]] = {
    if (derSignature.length < 8 || derSignature(0) != 48)
      me.raiseError(GeneralSignatureError("Invalid ECDSA signature format"))

    var offset: Int = 0
    if (derSignature(1) > 0) offset = 2
    else if (derSignature(1) == 0x81.toByte) offset = 3
    else me.raiseError(GeneralSignatureError("Invalid ECDSA signature format"))

    val rLength: Byte = derSignature(offset + 1)
    var i: Int        = rLength
    while ((i > 0) && (derSignature((offset + 2 + rLength) - i) == 0)) {
      i -= 1
    }

    val sLength: Byte = derSignature(offset + 2 + rLength + 1)
    var j: Int        = sLength
    while ((j > 0) && (derSignature((offset + 2 + rLength + 2 + sLength) - j) == 0)) {
      j -= 1
    }

    var rawLen: Int = Math.max(i, j)
    rawLen = Math.max(rawLen, ecTag.outputLen / 2)

    if ((derSignature(offset - 1) & 0xff) != derSignature.length - offset
        || (derSignature(offset - 1) & 0xff) != 2 + rLength + 2 + sLength
        || derSignature(offset) != 2 || derSignature(offset + 2 + rLength) != 2)
      me.raiseError(GeneralSignatureError("Invalid ECDSA signature format"))

    val concatSignature: Array[Byte] = new Array[Byte](2 * rawLen)
    System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i)
    System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j)
    me.pure(concatSignature)
  }

  /**
    * Signature transcode to der as required by the JCA.
    * Adapted from the implementation in scala-jwt, which itself was adapted from
    * jose4j, which itself was adapted from from org.apache.xml.security.algorithms.implementations.SignatureECDSA in the
    * (Apache 2 licensed) Apache Santuario XML Security library.
    *
    *
    * @param signature the signature to conver to DER
    * @param me MonadError Instance
    * @tparam F
    * @tparam A
    * @return
    */
  def concatSignatureToDER[F[_], A](signature: Array[Byte])(implicit me: MonadError[F, Throwable]): F[Array[Byte]] = {
    var (r, s) = signature.splitAt(signature.length / 2)
    r = r.dropWhile(_ == 0)
    if (r.length > 0 && r(0) < 0)
      r +:= 0.toByte

    s = s.dropWhile(_ == 0)
    if (s.length > 0 && s(0) < 0)
      s +:= 0.toByte

    val signatureLength = 2 + r.length + 2 + s.length
    if (signatureLength > 255)
      me.raiseError(GeneralSignatureError("Invalid ECDSA signature format"))

    var signatureDER = scala.collection.mutable.ListBuffer.empty[Byte]
    signatureDER += 48
    if (signatureLength >= 128)
      signatureDER += 0x81.toByte

    signatureDER += signatureLength.toByte
    signatureDER += 2.toByte += r.length.toByte ++= r
    signatureDER += 2.toByte += s.length.toByte ++= s

    me.pure(signatureDER.toArray)
  }
}
