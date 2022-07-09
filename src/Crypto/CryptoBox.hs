{-# LANGUAGE ImportQualifiedPost #-}
-- | As described in Crypto.Tutorial in cryptonite.
-- https://github.com/haskell-crypto/cryptonite/blob/master/Crypto/Tutorial.hs
module Crypto.CryptoBox where

import Data.ByteArray qualified as BA
import Data.ByteString qualified as B

import Crypto.Cipher.XSalsa qualified as XSalsa
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.PubKey.Curve25519 qualified as X25519
import Crypto.Error (CryptoFailable(..), maybeCryptoError, CryptoError(..))
import Crypto.ECC qualified as ECC
import Data.Maybe (fromJust)
import Data.Data (Proxy(..))

-- | Build a @crypto_box@ packet encrypting the specified content with a
-- 192-bit nonce, receiver public key and sender private key.
crypto_box
    :: B.ByteString
    -- ^ Message to encrypt
    -> B.ByteString
    -- ^ 192-bit nonce
    -> X25519.PublicKey
    -- ^ Public Key
    -> X25519.SecretKey
    -- ^ Private Key
    -> CryptoFailable B.ByteString
    -- ^ Ciphertext
crypto_box content nonce pk sk = do
    let zero = B.replicate 16 0
    shared <- ECC.ecdh (Proxy :: Proxy ECC.Curve_X25519) sk pk
    let (iv0, iv1) = B.splitAt 8 nonce
    let state0 = XSalsa.initialize 20 shared (zero `B.append` iv0)
    let state1 = XSalsa.derive state0 iv1
    let (rs, state2) = XSalsa.generate state1 32
    let (c, _) = XSalsa.combine state2 content
    let tag = Poly1305.auth (rs :: B.ByteString) c
    return $ BA.convert tag `B.append` c

crypto_box_beforenm
    :: X25519.PublicKey
    -> X25519.SecretKey
    -> CryptoFailable ECC.SharedSecret
crypto_box_beforenm pk sk = do
    let zero = B.replicate 16 0
    ECC.ecdh (Proxy :: Proxy ECC.Curve_X25519) sk pk

crypto_box_afternm
    :: B.ByteString
    -> B.ByteString
    -> ECC.SharedSecret
    -> B.ByteString
crypto_box_afternm content nonce shared = BA.convert tag `B.append` c
  where
    zero         = B.replicate 16 0
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
