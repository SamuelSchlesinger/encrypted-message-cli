{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE TypeApplications #-}
module Messaging where

import Data.Time.Clock
import Data.Binary (encodeFile, decodeFile, Binary(get, put), encode, decodeOrFail)
import Crypto.PubKey.RSA (generate, PrivateKey(..), PublicKey(..))
import Crypto.PubKey.RSA.OAEP (encrypt, decrypt, defaultOAEPParams)
import Crypto.PubKey.RSA.PSS (sign, defaultPSSParams, verify)
import Crypto.Hash (SHA512(SHA512))
import Options.Commander
import qualified Data.ByteString.Char8 as BS8
import qualified GHC.Generics
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Control.Monad (when)

newtype PrivateKeyFile = PrivateKeyFile { unPrivateKeyFile :: PrivateKey }
newtype PublicKeyFile = PublicKeyFile { unPublicKeyFile :: PublicKey }

data SecretMessage = SecretMessage
  { signature :: BS.ByteString
  , message :: BS.ByteString
  } deriving stock GHC.Generics.Generic
    deriving anyclass Binary

instance Binary PrivateKeyFile where
  put (PrivateKeyFile PrivateKey{..}) = do
    put (PublicKeyFile private_pub)
    put private_d
    put private_p
    put private_q
    put private_dP
    put private_dQ
    put private_qinv
  get = PrivateKeyFile <$> (PrivateKey <$> (unPublicKeyFile <$> get) <*> get <*> get <*> get <*> get <*> get <*> get)

instance Binary PublicKeyFile where
  put (PublicKeyFile PublicKey{..}) = do
    put public_size
    put public_n
    put public_e
  get = PublicKeyFile <$> (PublicKey <$> get <*> get <*> get)

type CMD = 
  Named "messaging"
  & Flag "verbose"
  & (
    "key"   & "new" 
            & Arg "name" [Char]
            & Raw

  + "write" & Arg "me" [Char] 
            & Arg "you" [Char]
            & Arg "file" String
            & Arg "message" String 
            & Raw

  + "read"  & Arg "me" [Char]
            & Arg "you" [Char]
            & Arg "file" FilePath
            & Raw
  )

program :: ProgramT CMD IO ()
program = named @"messaging" $ flag @"verbose" $ \verbose -> keypair verbose :+: write verbose :+: read verbose
  where
    read verbose =
      sub @"read" 
      $ arg @"me" \me -> 
        arg @"you" \you ->
        arg @"file" \source -> raw do
          when verbose $ putStrLn "reading message"
          privateKey <- unPrivateKeyFile <$> decodeFile (me <> ".private")
          publicKey <- unPublicKeyFile <$> decodeFile (you <> ".public")
          bs <- BS.readFile source
          case decodeOrFail (BSL.fromStrict bs) of
            Left e -> do
              when verbose $ putStrLn "decoding error:" >> print e
            Right (_, _, SecretMessage sig msg) -> do
                case decrypt Nothing (defaultOAEPParams SHA512) privateKey msg of
                  Left e -> do
                    when verbose $ putStr "decryption error:" >> print e
                  Right untwisted ->
                    if verify (defaultPSSParams SHA512) publicKey untwisted sig
                      then putStrLn $ BS8.unpack untwisted
                    else when verbose $ putStrLn "could not verify signature"

    write verbose = 
      sub @"write" 
      $ arg \me ->
        arg \you ->
        arg \file ->
        arg \message -> raw do
          let bsMsg = BS8.pack message
          when verbose $ putStrLn "authoring message"
          privateKey <- unPrivateKeyFile <$> decodeFile (me <> ".private")
          publicKey <- unPublicKeyFile <$> decodeFile (you <> ".public")
          signature <- sign Nothing (defaultPSSParams SHA512) privateKey bsMsg
          case signature of
            Left e -> do
              when verbose $ putStr "signature error: " >> print e
            Right sig -> do
              encryptedMsg <- encrypt (defaultOAEPParams SHA512) publicKey bsMsg
              case encryptedMsg of
                Left e -> do
                  when verbose $ putStr "encryption error: " >> print e
                Right twisted -> encodeFile file (SecretMessage sig twisted)

    keypair verbose =
      sub @"key" 
      $ sub @"new" 
      $ arg \name -> raw do
          when verbose $ putStrLn "generating keypair"
          (publicKey, privateKey) <- generate 2048 0x10001
          encodeFile (name <> ".public") (PublicKeyFile publicKey)
          encodeFile (name <> ".private") (PrivateKeyFile privateKey)

main :: IO ()
main = command_ (program :+: sub @"help" (usage @CMD) :+: raw (putStrLn "try: messaging help"))
