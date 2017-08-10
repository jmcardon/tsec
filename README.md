# tsec: A pure, general purpose crypto library.

(WIP)

## RoadMap:

JCA:
- [x] MessageDigests
- [ ] Symmetric ciphers (Missing PBE, blowfish and ARCFOUR)
- [ ] Asymmetric Ciphers
- [ ] KeyGenerators and key construction in general (WIP, partly)
- [ ] KeySpec
- [ ] Mac
- [ ] AlgorithmParameter and generators
- [ ] Other digital signature and ssl related stuff (backburner, low uses cases)

Sphlib
- [ ] [Integrate sphlib hashing](http://www.saphir2.com/sphlib/)

Password Hashing:
- [x] BCrypt (jBCrypt)
- [x] SCrypt (wg/scrypt)
- [ ] PBKDF2 (wg)
- [ ] PBKDF2 (JCA)
- [ ] Pure Scala BCrypt
- [ ] Pure Scala SCrypt

Server-side app goodies
- [ ] JWT - Jose4J integration
- [ ] (Possibly?) Our own JWT implementation using our own algebras and primitives.
- [ ] Common session token crypto schemes
- [ ] Http4s authentication via an arbitrary mechanism (Priority 1)
- [ ] Akka-http authentication (Priority 2)
- [ ] Play-http authentication (Optional, play already has silhouette)

BouncyCastle:
- [ ] MessageDigests
- [ ] Symmetric ciphers
- [ ] Asymmetric Ciphers
- [ ] KeyGenerators and key construction in general 4
- [ ] KeySpec
- [ ] Mac
- [ ] AlgorithmParameter and generators
- [ ] Other digital signature and ssl related stuff (backburner, low uses cases)


### Other things on the list:
- Articles and education. We might not be opinionated about exact ciphers being used


#### More resources:


 JCA: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html
 https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
 https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid
 
 Passwords:
 https://stackoverflow.com/questions/8881291/why-is-char-preferred-over-string-for-passwords
 
 Mode:
 https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
 

Padding schemes: 
  https://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
  https://crypto.stackexchange.com/questions/10775/practical-disadvantages-of-gcm-mode-encryption
  https://developer.android.com/reference/javax/crypto/Cipher.html <- good resource for common combinations