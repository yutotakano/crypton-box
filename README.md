# shecretbox

Shecretbox is a Haskell library that provides NaCl's [box](https://nacl.cr.yp.to/box.html) and [secretbox](https://nacl.cr.yp.to/secretbox.html) operations, based on primitives provided in [`cryptonite`](https://hackage.haskell.org/package/cryptonite).

**Important**: This library is provided as a proof of concept, please carefully evaluate the security related to your requirements before using. No professional security review has taken place for the implementations, and it is **strongly recommended** not to use this library for anything critical.

## Use

Qualified imports are recommended for use:

```hs
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.Box as Box

message, nonce :: B.ByteString
secret :: X25519.DhSecret

encrypted :: B.ByteString
encrypted = Box.create message nonce secret

decrypted :: B.ByteString
decrypted = Box.open message nonce secret
```
