{-# LANGUAGE TypeOperators #-}
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
import Control.Monad (when)

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

type CMD = 
  Named "messaging"
  & Flag "verbose"
  &   (("key" & ("new" & (Arg "keyPairName" [Char] & Raw)))
    + (("write" & (Arg "publicKey" [Char] & (Arg "secretMessage" String & Raw)))
    + ("read" & (Arg "privateKey" [Char] & (Arg "secretMessageFile" FilePath & Raw)))))

program :: ProgramT CMD IO ()
program = named @"messaging" $ flag @"verbose" $ \verbose -> keypair verbose :+: author verbose :+: read verbose
  where
    read verbose = sub @"read" $ arg @"privateKey" \privateKeyFile -> arg @"secretMessageFile" \source -> raw do
      when verbose $ putStrLn "reading message"
      privateKey <- unPrivateKeyFile <$> decodeFile (privateKeyFile <> ".private")
      bs <- BS.readFile source
      let decrypted = decrypt Nothing (defaultOAEPParams SHA512) privateKey bs
      case decrypted of
        Left e -> do
          when verbose $ putStr "decryption error:" >> print e
        Right untwisted -> putStrLn $ BS8.unpack untwisted
    author verbose = sub @"write" $ arg @"publicKey" \to -> arg @"secretMessage" \msg -> raw do
      putStrLn "authoring message"
      time <- getCurrentTime
      publicKey <- unPublicKeyFile <$> decodeFile (to <> ".public")
      encrypted <- encrypt (defaultOAEPParams SHA512) publicKey (BS8.pack msg)
      case encrypted of
        Left e -> do
          when verbose $ putStr "encryption error: " >> print e
        Right twisted -> BS.writeFile (to <> ":" <> show time) twisted 
    keypair verbose = sub @"key" $ sub @"new" $ arg @"keyPairName" \name -> raw do
      when verbose $ putStrLn "generating keypair"
      (publicKey, privateKey) <- generate 2048 0x10001
      encodeFile (name <> ".public") (PublicKeyFile publicKey)
      encodeFile (name <> ".private") (PrivateKeyFile privateKey)

main :: IO ()
main = command_ (program :+: sub @"help" (usage @CMD) :+: raw (putStrLn "try: messaging help"))
