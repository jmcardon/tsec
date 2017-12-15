package tsec.libsodium.kx

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.SodiumKey
import tsec.libsodium.pk.{PrivateKey, PublicKey, SodiumKeyPair}

sealed trait KeyExchange

object KeyExchange {

  def generateKeyPair[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair[KeyExchange]] = F.delay {
    val pk = new Array[Byte](ScalaSodium.crypto_kx_PUBLICKEYBYTES)
    val sk = new Array[Byte](ScalaSodium.crypto_kx_SECRETKEYBYTES)

    S.crypto_kx_keypair(pk, sk)

    SodiumKeyPair(PublicKey[KeyExchange](pk), PrivateKey[KeyExchange](sk))
  }

  def generateKeyPairSeed[F[_]](seed: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair[KeyExchange]] = F.delay {
    if (seed.length != ScalaSodium.crypto_kx_SEEDBYTES)
      throw KeySeedingError(seed.length)

    val pk = new Array[Byte](ScalaSodium.crypto_kx_PUBLICKEYBYTES)
    val sk = new Array[Byte](ScalaSodium.crypto_kx_SECRETKEYBYTES)

    S.crypto_kx_seed_keypair(pk, sk, seed)

    SodiumKeyPair(PublicKey[KeyExchange](pk), PrivateKey[KeyExchange](sk))
  }

  def generateClientSessionKeys[F[_]](
      keyPair: SodiumKeyPair[KeyExchange],
      server: PublicKey[KeyExchange]
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumSharedKeyPair[KeyExchange]] = F.delay {
    val rx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)
    val tx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)

    if (S.crypto_kx_client_session_keys(rx, tx, keyPair.pubKey, keyPair.privKey, server) != 0)
      throw KeySessionError

    SodiumSharedKeyPair[KeyExchange](SodiumKey(rx), SodiumKey(tx))
  }

  def generateServerSessionKeys[F[_]](
      keyPair: SodiumKeyPair[KeyExchange],
      client: PublicKey[KeyExchange]
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumSharedKeyPair[KeyExchange]] = F.delay {
    val rx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)
    val tx = new Array[Byte](ScalaSodium.crypto_kx_SESSIONKEYBYTES)

    if (S.crypto_kx_server_session_keys(rx, tx, keyPair.pubKey, keyPair.privKey, client) != 0)
      throw KeySessionError

    SodiumSharedKeyPair[KeyExchange](SodiumKey(rx), SodiumKey(tx))
  }
}
