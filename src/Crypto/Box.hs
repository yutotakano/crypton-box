{-# LANGUAGE ImportQualifiedPost #-}
-- | As described in Crypto.Tutorial in cryptonite.
-- https://github.com/haskell-crypto/cryptonite/blob/master/Crypto/Tutorial.hs
module Crypto.Box where

import Crypto.Cipher.Salsa (State(..))
import Crypto.Cipher.XSalsa qualified as XSalsa
import Crypto.ECC qualified as ECC
import Crypto.Error (CryptoFailable(..))
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.PubKey.Curve25519 qualified as X25519
import Data.ByteArray qualified as BA
import Data.ByteString qualified as B
import Data.Data (Proxy(..))
import Data.Function ((&))
import Data.Foldable (traverse_)
import Foreign.Ptr qualified as Ptr
import Foreign.Storable qualified as Storable
import GHC.IO (unsafePerformIO)

-- | Build a @crypto_box@ packet encrypting the specified content with a
-- 192-bit nonce, receiver public key and sender private key.
--
-- This function performs no validation for the key pair, and will use an
-- all-zero shared secret if the Diffie hellman secret value is at infinity.
-- Use 'Box.beforeNM' to get only the precomputed secret if you want to verify
-- the key pair before use.
create
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Message to encrypt
    -> nonce
    -- ^ 192-bit nonce
    -> X25519.PublicKey
    -- ^ Receiver's public key
    -> X25519.SecretKey
    -- ^ Sender's private key
    -> content
    -- ^ Ciphertext
create message nonce pk sk = BA.convert tag `BA.append` c
  -- convert the tag from Auth to ByteString (reallocating), instead of
  -- converting both of them to a polymorphic (ByteArrayAccess ciphertext),
  -- preventing unnecessary conversion. People who need other byte access types
  -- can convert it themselves.
  where
    shared = X25519.dh pk sk
    (iv0, iv1) = BA.splitAt 8 nonce
    zero = BA.zero 16
    state0 = XSalsa.initialize 20 shared (zero `BA.append` iv0)
    state1 = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (c, _) = XSalsa.combine state2 message
    tag = Poly1305.auth (rs :: B.ByteString) c

-- | Precompute the shared key for building a @crypto_box@ packet.
-- This function first computes the shared secret using the receiver public key
-- and sender private key. Then, a first-level key is computed using HSalsa20
-- with the shared secret and a nonce of zero. This is as described in section
-- 7 (page 15) of https://cr.yp.to/highspeed/naclcrypto-20090310.pdf.
--
-- The function returns a XSalsa State that contains the first-level key.
--
-- May fail if the Diffie hellman secret value is at infinity. See 'ECC.ecdh' for
-- more information.
beforeNM
    :: X25519.PublicKey
    -- ^ Receiver public key
    -> X25519.SecretKey
    -- ^ Sender private key
    -> CryptoFailable XSalsa.State
    -- ^ XSalsa State that contains the precomputed first-level key to use with 'createAfterNM' or 'openAfterNM'
beforeNM pk sk = do
    let zero = B.replicate 24 0
    shared <- ECC.ecdh (Proxy :: Proxy ECC.Curve_X25519) sk pk
    pure $ XSalsa.initialize 20 shared zero

-- | Build a @crypto_box@ packet that encrypts the specified content with a
-- 192-bit nonce and a state containing the precomputed first-level key.
-- Use 'beforeNM' to create such a state.
createAfterNM
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Message to encrypt
    -> nonce
    -- ^ 192-bit nonce
    -> XSalsa.State
    -- ^ XSalsa State that contains the precomputed first-level key
    -> content
    -- ^ Ciphertext
createAfterNM message nonce (State state0) = BA.convert tag `BA.append` c
  where
    zero       = B.replicate 16 0
    (iv0, iv1) = BA.splitAt 8 nonce
    -- This is very hacky. The XSalsa.initialise that we performed in the beforeNM
    -- stage has mostly what we need, except for state[6] and state[7] which is
    -- where the first 8 bytes of the IV/nonce go to. Since those are currently
    -- zero because we used zeros during the beforeNM (we didn't know the nonce),
    -- we now need to poke into that pointer location and overwrite its contents.
    state1     = unsafePerformIO $ do
        memview <- BA.withByteArray state0 $ \state0Ptr -> do
            -- We start writing at byte 24, this is 6*4 where 6 is the location
            -- that the 16th byte of the 24-byte IV (the first 16 are zeros even
            -- if we use cryptoBox) passed to xsalsa is written to, and 4 is
            -- because the base type is uint32.
            --
            -- TODO: This currently relies on the system endianness since we're
            -- writing the nonce bytes one by one instead of as a little-endian
            -- 32-bit chunk. This needs to be made system-agnostic.
            BA.unpack iv0
                & zip [24..31]
                & traverse_ (\(i, word) ->
                    Storable.poke (state0Ptr `Ptr.plusPtr` i) word)
            -- Return the 132 bytes that is the size of the State struct
            -- This is how much is allocated when you look at the source of
            -- XSalsa.initialize, and the struct contents are defined here:
            -- https://github.com/haskell-crypto/cryptonite/blob/cf89276b5cdd87fcd60cce2fb424e64f0de7016a/cbits/cryptonite_salsa.h
            pure $ BA.MemView state0Ptr 132
        -- Convert from a pointer to Words to a pointer to State
        pure $ State $ BA.convert $ memview

    state2       = XSalsa.derive state1 iv1
    (rs, state3) = XSalsa.generate state2 32
    (c, _)       = XSalsa.combine state3 message
    tag          = Poly1305.auth (rs :: B.ByteString) c

-- | Try to open a @crypto_box@ packet and recover the content using the
-- 192-bit nonce, sender public key and receiver private key.
--
-- This function performs no validation for the key pair, and will use an
-- all-zero shared secret if the Diffie hellman secret value is at infinity.
-- Use 'Box.beforeNM' to get only the precomputed secret if you want to verify
-- the key pair before use.
open
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Ciphertext to decrypt
    -> nonce
    -- ^ 192-bit nonce
    -> X25519.PublicKey
    -- ^ Sender's public key
    -> X25519.SecretKey
    -- ^ Receiver's private key
    -> Maybe content
    -- ^ Plaintext
open packet nonce pk sk
    | BA.length packet < 16 = Nothing
    | BA.constEq tag' tag  = Just content
    | otherwise            = Nothing
  where
    (tag', c)    = BA.splitAt 16 packet
    zero         = BA.zero 16
    shared       = X25519.dh pk sk
    (iv0, iv1)   = BA.splitAt 8 nonce
    state0       = XSalsa.initialize 20 shared (zero `BA.append` iv0)
    state1       = XSalsa.derive state0 iv1
    (rs, state2) = XSalsa.generate state1 32
    (content, _) = XSalsa.combine state2 c
    tag          = Poly1305.auth (rs :: B.ByteString) c

-- | Try to open a @crypto_box@ packet and recover the content using the
-- 192-bit nonce and a state containing the precomputed first-level key.
-- Use 'beforeNM' to create such a state.
openAfterNM
    :: (BA.ByteArray content, BA.ByteArray nonce)
    => content
    -- ^ Ciphertext
    -> nonce
    -- ^ 192-bit nonce
    -> XSalsa.State
    -- ^ XSalsa State that contains the precomputed first-level key
    -> Maybe content
openAfterNM packet nonce (State state0)
    | BA.length packet < 16 = Nothing
    | BA.constEq tag' tag  = Just content
    | otherwise            = Nothing
  where
    (tag', c)    = BA.splitAt 16 packet
    (iv0, iv1)   = BA.splitAt 8 nonce

    -- This is very hacky. The XSalsa.initialise that we performed in the beforeNM
    -- stage has mostly what we need, except for state[6] and state[7] which is
    -- where the first 8 bytes of the IV/nonce go to. Since those are currently
    -- zero because we used zeros during the beforeNM (we didn't know the nonce),
    -- we now need to poke into that pointer location and overwrite its contents.
    state1     = unsafePerformIO $ do
        memview <- BA.withByteArray state0 $ \state0Ptr -> do
            -- We start writing at byte 24, this is 6*4 where 6 is the location
            -- that the 16th byte of the 24-byte IV (the first 16 are zeros even
            -- if we use cryptoBox) passed to xsalsa is written to, and 4 is
            -- because the base type is uint32.
            BA.unpack iv0
                & zip [24..31]
                & traverse_ (\(i, word) ->
                    Storable.poke (state0Ptr `Ptr.plusPtr` i) word)
            -- Return the 132 bytes that is the size of the State struct
            -- This is how much is allocated when you look at the source of
            -- XSalsa.initialize, and the struct contents are defined here:
            -- https://github.com/haskell-crypto/cryptonite/blob/cf89276b5cdd87fcd60cce2fb424e64f0de7016a/cbits/cryptonite_salsa.h
            pure $ BA.MemView state0Ptr 132
        -- Convert from a pointer to Words to a pointer to State
        pure $ State $ BA.convert $ memview

    state2       = XSalsa.derive state1 iv1
    (rs, state3) = XSalsa.generate state2 32
    (content, _) = XSalsa.combine state3 c
    tag          = Poly1305.auth (rs :: B.ByteString) c
