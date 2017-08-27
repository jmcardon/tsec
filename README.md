# tsec: A pure, general purpose crypto library.

(WIP)

## RoadMap:

JCA:
- [x] MessageDigests
- [X] Symmetric ciphers
- [ ] Asymmetric Ciphers
- [ ] KeyGenerators and key construction in general (WIP, partly)
- [X] Signatures
- [X] Mac
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

http://www.fi.muni.cz/~xsvenda/docs/AE_comparison_ipics04.pdf


 JCA: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html
 https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
 https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid
 https://developer.android.com/reference/javax/crypto/Cipher.html <- good resource for common combinations
 https://tools.ietf.org/html/rfc5116
 http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 https://crypto.stackexchange.com/questions/6842/how-to-choose-between-aes-ccm-and-aes-gcm-for-storage-volume-encryption
 https://tools.ietf.org/html/rfc5116
 https://security.stackexchange.com/questions/2202/lessons-learned-and-misconceptions-regarding-encryption-and-cryptology/2213#2213
 https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/
 
 
 Passwords:
 https://stackoverflow.com/questions/8881291/why-is-char-preferred-over-string-for-passwords
 
 Mode:
 https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
 

Padding schemes: 
  https://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
  https://crypto.stackexchange.com/questions/10775/practical-disadvantages-of-gcm-mode-encryption
  
SecureRandom:
https://www.synopsys.com/blogs/software-security/proper-use-of-javas-securerandom/
https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/

HMac
https://tools.ietf.org/html/rfc2104
https://tools.ietf.org/html/rfc4868
NOTE: Hmac keys should not be smaller than the output length

JWT
https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3

Signatures:
https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1/1797#1797