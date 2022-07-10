{-# LANGUAGE ImportQualifiedPost #-}
module Crypto.SecretBox where

import Data.ByteArray qualified as BA
import Data.ByteString qualified as B

import Crypto.Cipher.XSalsa qualified as XSalsa
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.PubKey.Curve25519 qualified as X25519

-- | Build a @secret_box@ packet encrypting the specified content with a
-- 192-bit nonce and a 256-bit symmetric secret key.
create
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Message to encrypt
    -> nonce
    -- ^ 192-bit nonce
    -> X25519.DhSecret
    -- ^ Symmetric secret key
    -> content
    -- ^ Ciphertext
create message nonce key = BA.convert tag `BA.append` c
  where
    -- No need to prepend 16 bytes of zero before the nonce and then call derive
    -- with the rest. This is because secret_box directly calls
    --   crypto_secretbox_xsalsa20poly1305
    -- which begins with the XOR-ing, while crypto_box calls
    --   crypto_box_curve25519xsalsa20poly1305_beforenm
    -- (which has a single HSalsa() round applied on the shared secret) before
    -- calling
    --   crypto_box_curve25519xsalsa20poly1305_afternm, which calls
    --   crypto_secretbox_xsalsa20poly1305
    --
    --
    -- So, since we already have a symmetric secret key that has one layer of
    -- HSalsa() performed on it, we can directly use that without calling "derive"
    -- twice (once in init and once in derive) and start performing the xor after
    -- the first HSalsa() in initialize.
    state0       = XSalsa.initialize 20 key nonce
    (rs, state1) = XSalsa.generate state0 32
    (c, _)       = XSalsa.combine state1 message
    tag          = Poly1305.auth (rs :: B.ByteString) c

-- | Try to open a @secret_box@ packet and recover the content using the
-- 192-bit nonce and a 256-bit symmetric secret key.
open
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Ciphertext to decrypt
    -> nonce
    -- ^ 192-bit nonce
    -> X25519.DhSecret
    -- ^ Symmetric secret key
    -> Maybe content
    -- ^ Message
open packet nonce key
    | BA.length packet < 16 = Nothing
    | BA.constEq tag' tag  = Just content
    | otherwise            = Nothing
  where
    (tag', c)    = BA.splitAt 16 packet
    state0       = XSalsa.initialize 20 key nonce
    (rs, state1) = XSalsa.generate state0 32
    (content, _) = XSalsa.combine state1 c
    tag          = Poly1305.auth (rs :: B.ByteString) c
