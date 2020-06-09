{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE TypeApplications #-}
module Main where

import Data.Time.Clock
import Data.Binary (encodeFile, decodeFile, Binary(get, put))
import Crypto.PubKey.RSA (generate, PrivateKey(..), PublicKey(..))
import Crypto.PubKey.RSA.OAEP (encrypt, decrypt, defaultOAEPParams)
import Crypto.Hash (SHA512(SHA512))
import Options.Commander
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS

newtype PrivateKeyFile = PrivateKeyFile { unPrivateKeyFile :: PrivateKey }
newtype PublicKeyFile = PublicKeyFile { unPublicKeyFile :: PublicKey }

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

main :: IO ()
main = command_ $ named @"messaging" $ keypair :+: author :+: read
  where
    read = sub @"read" $ arg @"name" \privateKeyFile -> arg @"source" \source -> raw do
      putStrLn "reading message"
      privateKey <- unPrivateKeyFile <$> decodeFile (privateKeyFile <> ".private")
      bs <- BS.readFile source
      let decrypted = decrypt Nothing (defaultOAEPParams SHA512) privateKey bs
      case decrypted of
        Left _error -> do
          putStr "decryption error: "
          print _error
        Right untwisted -> putStrLn $ BS8.unpack untwisted
    author = sub @"author" $ arg @"to" \to -> arg @"message" \msg -> raw do
      putStrLn "authoring message"
      time <- getCurrentTime
      publicKey <- unPublicKeyFile <$> decodeFile (to <> ".public")
      encrypted <- encrypt (defaultOAEPParams SHA512) publicKey (BS8.pack msg)
      case encrypted of
        Left _error -> do
          putStr "encryption error: "
          print _error
        Right twisted -> encodeFile (to <> ":" <> show time) twisted 
    keypair = sub @"keypair" $ arg @"name" \name -> raw do
      putStrLn "generating keypair"
      (publicKey, privateKey) <- generate 2048 0x10001
      encodeFile (name <> ".public") (PublicKeyFile publicKey)
      encodeFile (name <> ".private") (PrivateKeyFile privateKey)
