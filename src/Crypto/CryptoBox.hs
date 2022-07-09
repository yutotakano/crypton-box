{-# LANGUAGE ImportQualifiedPost #-}
-- | As described in Crypto.Tutorial in cryptonite.
-- https://github.com/haskell-crypto/cryptonite/blob/master/Crypto/Tutorial.hs
module Crypto.CryptoBox where

import Data.ByteArray qualified as BA
import Data.ByteString qualified as B

import Crypto.Cipher.XSalsa qualified as XSalsa
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.PubKey.Curve25519 qualified as X25519

-- | Build a @crypto_box@ packet encrypting the specified content with a
-- 192-bit nonce, receiver public key and sender private key.
crypto_box
    :: B.ByteString
    -> B.ByteString
    -> X25519.PublicKey
    -> X25519.SecretKey
    -> B.ByteString
crypto_box content nonce pk sk = BA.convert tag `B.append` c
  where
    zero         = B.replicate 16 0
    shared       = X25519.dh pk sk
    (iv0, iv1)   = B.splitAt 8 nonce
    state0       = XSalsa.initialize 20 shared (zero `B.append` iv0)
    state1       = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (c, _)       = XSalsa.combine state2 content
    tag          = Poly1305.auth (rs :: B.ByteString) c

-- | Try to open a @crypto_box@ packet and recover the content using the
-- 192-bit nonce, sender public key and receiver private key.
crypto_box_open
    :: B.ByteString
    -> B.ByteString
    -> X25519.PublicKey
    -> X25519.SecretKey
    -> Maybe B.ByteString
crypto_box_open packet nonce pk sk
    | B.length packet < 16 = Nothing
    | BA.constEq tag' tag  = Just content
    | otherwise            = Nothing
  where
    (tag', c)    = B.splitAt 16 packet
    zero         = B.replicate 16 0
    shared       = X25519.dh pk sk
    (iv0, iv1)   = B.splitAt 8 nonce
    state0       = XSalsa.initialize 20 shared (zero `B.append` iv0)
    state1       = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (content, _) = XSalsa.combine state2 c
    tag          = Poly1305.auth (rs :: B.ByteString) c
