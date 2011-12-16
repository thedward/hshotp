{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Data.HMAC.OTP.HOTP
  ( hotp
  , count
  , utcCount'
  , utcCount
  , utcCountDefaultStep
  , decodeHexKey
  , encodeHexKey
  )
where

import Data.HMAC (hmac_sha1)
import Codec.Utils (fromTwosComp,toTwosComp,Octet(..))
import Data.Bits ((.&.))
import Data.Word (Word64)
import Data.Time.Clock.POSIX (POSIXTime)
import Data.Time.Clock (UTCTime(..),diffUTCTime,NominalDiffTime(..))
import Data.Time.Calendar (fromGregorian)
import Data.String (fromString)
import Data.List.Split (chunk)
import Data.Maybe (listToMaybe)
import Numeric (readHex,showHex)
import qualified Codec.Binary.Base32 as Base32

newtype Count = Count Word64 deriving (Show,Eq,Enum,Num)

hotp :: [Octet] -> Count -> Int -> Int
hotp k (Count c) d = fromTwosComp sbits `mod` (10^d)
  where sbits = dt ( hmac_sha1 k cs )
        cs = pad (toTwosComp c)
        pad xs = if length xs < 8 then pad (0:xs) else xs
        dt :: [Octet] -> [Octet]
        dt st = ( p .&. 0x7f ) : ps
          where offset = fromIntegral $ ( st' !! 19 ) .&. 0xf
                (p:ps) = take 4 ( drop offset st' )
                st'    = pad st
                pad xs = if length xs < 20 then pad (0:xs) else xs


count = Count . fromIntegral

utcCount' start step now = Count $ floor ( diffUTCTime now start / step )

utcCount step = utcCount' defaultStartTime step

utcCountDefaultStep = utcCount 30

defaultStartTime = UTCTime (fromGregorian 1970 1 1) 0

decodeHexKey :: String -> Maybe [Octet]
decodeHexKey = sequence . map (fmap fst . listToMaybe . readHex) . chunk 2

encodeHexKey :: [Octet] -> String
encodeHexKey = concatMap (pad . flip showHex "")
  where pad x@[_,_] = x
        pad x@[_] = '0':x

decodeBase32Key :: String -> Maybe [Octet]
decodeBase32Key = Base32.decode

encodeBase32Key :: [Octet] -> String
encodeBase32Key = Base32.encode

