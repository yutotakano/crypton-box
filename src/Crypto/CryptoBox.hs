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
--
-- This function performs no validation for the key pair, and will use an
-- all-zero shared secret if the Diffie hellman secret value is at infinity.
-- Use 'crypto_box_beforenm' to get just a CryptoFailable-wrapped precomputed
-- secret if you want to verify the key pair.
crypto_box
    :: B.ByteString
    -- ^ Message to encrypt
    -> B.ByteString
    -- ^ 192-bit nonce
    -> X25519.PublicKey
    -- ^ Public Key
    -> X25519.SecretKey
    -- ^ Private Key
    -> B.ByteString
    -- ^ Ciphertext
crypto_box content nonce pk sk = BA.convert tag `B.append` c
  where
    shared = X25519.dh pk sk
    (iv0, iv1) = B.splitAt 8 nonce
    zero = B.replicate 16 0
    state0 = XSalsa.initialize 20 shared (zero `B.append` iv0)
    state1 = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (c, _) = XSalsa.combine state2 content
    tag = Poly1305.auth (rs :: B.ByteString) c

-- | Precompute the shared key for building a @crypto_box@ packet, using the
-- receiver public key and sender private key.
crypto_box_beforenm
    :: X25519.PublicKey
    -- ^ Receiver public key
    -> X25519.SecretKey
    -- ^ Sender private key
    -> CryptoFailable ECC.SharedSecret
    -- ^ Precomputed shared secret to use with 'crypto_box_afternm'
crypto_box_beforenm pk sk = do
    let zero = B.replicate 16 0
    ECC.ecdh (Proxy :: Proxy ECC.Curve_X25519) sk pk

-- | Build a @crypto_box@ packet that encrypts the specified content with a
-- 192-bit nonce and a precomputed shared secret.
crypto_box_afternm
    :: B.ByteString
    -- ^ Message to encrypt
    -> B.ByteString
    -- ^ 192-bit nonce
    -> ECC.SharedSecret
    -- ^ Precomputed shared secret
    -> B.ByteString
    -- ^ Ciphertext
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

crypto_box_open_afternm
    :: B.ByteString
    -> B.ByteString
    -> ECC.SharedSecret
    -> Maybe B.ByteString
crypto_box_open_afternm packet nonce shared
    | B.length packet < 16 = Nothing
    | BA.constEq tag' tag  = Just content
    | otherwise            = Nothing
  where
    (tag', c)    = B.splitAt 16 packet
    zero         = B.replicate 16 0
    (iv0, iv1)   = B.splitAt 8 nonce
    state0       = XSalsa.initialize 20 shared (zero `B.append` iv0)
    state1       = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (content, _) = XSalsa.combine state2 c
    tag          = Poly1305.auth (rs :: B.ByteString) c
