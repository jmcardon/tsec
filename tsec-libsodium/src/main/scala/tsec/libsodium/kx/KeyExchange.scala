package tsec.libsodium.kx

import cats.effect.Sync
import tsec.libsodium.ScalaSodium

object KeyExchange {

  def generateKeyPair[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair] = F.delay {
    val pk = new Array[Byte](ScalaSodium.crypto_kx_PUBLICKEYBYTES)
    val sk = new Array[Byte](ScalaSodium.crypto_kx_SECRETKEYBYTES)

    S.crypto_kx_keypair(pk, sk)

    SodiumKeyPair(SodiumKey$$.is[PublicKey].coerce(pk), SodiumKey$$.is[SecretKey].coerce(sk))
  }

  def generateKeyPairSeed[F[_]](seed: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair] = F.delay {
    if (seed.length != ScalaSodium.crypto_kx_SEEDBYTES)
      throw KeySeedingError(seed.length)

    val pk = new Array[Byte](ScalaSodium.crypto_kx_PUBLICKEYBYTES)
    val sk = new Array[Byte](ScalaSodium.crypto_kx_SECRETKEYBYTES)

    S.crypto_kx_seed_keypair(pk, sk, seed)

    SodiumKeyPair(SodiumKey$$.is[PublicKey].coerce(pk), SodiumKey$$.is[SecretKey].coerce(sk))
  }

  def generateClientSessionKeys[F[_]](
      keyPair: SodiumKeyPair,
      server: SodiumKey[PublicKey]
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumSharedKeyPair] = F.delay {
    val rx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)
    val tx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)

    if (S.crypto_kx_client_session_keys(rx, tx, keyPair.pk, keyPair.sk, server) != 0)
      throw KeySessionError

    SodiumSharedKeyPair(SodiumKey$$.is[SharedKey].coerce(rx), SodiumKey$$.is[SharedKey].coerce(tx))
  }

  def generateServerSessionKeys[F[_]](
      keyPair: SodiumKeyPair,
      client: SodiumKey[PublicKey]
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumSharedKeyPair] = F.delay {
    val rx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)
    val tx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)

    if (S.crypto_kx_server_session_keys(rx, tx, keyPair.pk, keyPair.sk, client) != 0)
      throw KeySessionError

    SodiumSharedKeyPair(SodiumKey$$.is[SharedKey].coerce(rx), SodiumKey$$.is[SharedKey].coerce(tx))
  }
}
