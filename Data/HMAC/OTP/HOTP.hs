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
import Codec.Utils (fromTwosComp,toTwosComp,Octet())
import Data.Bits ((.&.))
import Data.Word (Word64)
import Data.Time.Clock (UTCTime(..),diffUTCTime)
import Data.Time.Calendar (fromGregorian)
import Data.List.Split (chunk)
import Data.Maybe (listToMaybe)
import Numeric (readHex,showHex)
import qualified Codec.Binary.Base32 as Base32

newtype Count = Count Word64 deriving (Show,Eq,Enum,Num,Ord,Real,Integral)

hotp :: [Octet] -> Count -> Int -> String
hotp k (Count c) d = fmt $ fromTwosComp sbits `mod` (10^d)
  where sbits = dynamicTruncate ( hmac_sha1 k cs )
        cs = zeroPad 8 (toTwosComp c)
        fmt :: Int -> String
        fmt n = padTo d '0' (show n)

dynamicTruncate st = ( p .&. 0x7f ) : ps
  where offset = fromIntegral $ ( st' !! 19 ) .&. 0xf
        (p:ps) = take 4 ( drop offset st' )
        st'    = zeroPad 20 st

padTo n x ys = if length ys < n then padTo n x (x:ys) else ys

zeroPad n xs = if length xs < n then zeroPad n (0:xs) else xs

count = Count . fromIntegral

utcCount' start step now = Count $ floor ( diffUTCTime now start / step )

utcCount = utcCount' defaultStartTime

utcCountDefaultStep = utcCount 30

defaultStartTime = UTCTime (fromGregorian 1970 1 1) 0

decodeHexKey :: String -> Maybe [Octet]
decodeHexKey = mapM (fmap fst . listToMaybe . readHex) . chunk 2

hexOctet :: Octet -> String
hexOctet o = case showHex o "" of
                  [x] -> ['0',x]
decodeHexKey = sequence . map (fmap fst . listToMaybe . readHex) . chunk 2

encodeHexKey :: [Octet] -> String
encodeHexKey = concatMap hexOctet

decodeBase32Key :: String -> Maybe [Octet]
decodeBase32Key = Base32.decode

encodeBase32Key :: [Octet] -> String
encodeBase32Key = Base32.encode

--verifyTOTP k v = (==v) . ( \c -> hotp k c 6 ) . utcCountDefaultStep <$> getCurrentTime
