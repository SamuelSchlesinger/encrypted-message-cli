{-# LANGUAGE TemplateHaskell #-}
module Main where

import Control.Monad (forM_)

import System.FilePath.TH (fileRelativeToAbsolute)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Char8 as BS8
import Messaging (encodeAndSignMessage, decodeAndVerifyMessage, generateKeypair, unPublicKeyFile, unPrivateKeyFile)
import Data.Binary (decodeFile)

main :: IO ()
main = do
  let keysPath = $(fileRelativeToAbsolute "keys")
  bobPublicKey <- unPublicKeyFile <$> decodeFile (keysPath <> "/bob.public")
  bobPrivateKey <- unPrivateKeyFile <$> decodeFile (keysPath <> "/bob.private")
  alicePublicKey <- unPublicKeyFile <$> decodeFile (keysPath <> "/alice.public")
  alicePrivateKey <- unPrivateKeyFile <$> decodeFile (keysPath <> "/alice.private")
  evePublicKey <- unPublicKeyFile <$> decodeFile (keysPath <> "/eve.public")
  evePrivateKey <- unPrivateKeyFile <$> decodeFile (keysPath <> "/eve.private")
  forM_ messages $ \x -> do
    Just encodedMsg <- encodeAndSignMessage bobPrivateKey alicePublicKey (show x)
    let Nothing = decodeAndVerifyMessage evePrivateKey bobPublicKey (BSL.toStrict encodedMsg)
    let Just decodedMsg = decodeAndVerifyMessage alicePrivateKey bobPublicKey (BSL.toStrict encodedMsg)
    if show x == decodedMsg then pure () else error "Decoding failed"

messages :: [String]
messages =
  ["Hello, this is Sam",
   "Pow chicka wow wow",
   "141241241",
   "HELLO WORLD",
   "!!!!!>..",
   "YES, THIS IS A VERY IMPORTANT MESSAGE ONLY HEADED FOR THE MOST IMPORTANT \
   \PLACES. INDEED, WE CAN REALLY ENCRYPT LONG MESSAGES OVER HERE. HOW LONG? \
   \I WOULDN'T STICK AROUND TO FIND OUT. IT'S GONNA BE A LONG TIME TIL WE CAN'T \
   \SEND A MESSAGE SO LONG. Oh indeed! The messages that I can encode are longer \
   \than long. We can really get going on this, make a real long message. Get \
   \yourself to long-town, bruski.",
   "",
   take 1850 $ repeat ' ']
