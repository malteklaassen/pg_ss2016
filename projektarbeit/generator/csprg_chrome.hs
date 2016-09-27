{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}

module Main where
import System.IO as SIO (Handle, IOMode (ReadMode, WriteMode), hIsEOF, hClose, hGetLine, hPutStr, openFile)

import Data.Map.Strict as DMS (Map, insertWith, fromListWith, unionWith, toList)
import qualified Data.Map.Strict as DMS (map, empty)

import Data.List as DL (isPrefixOf, nub, intersperse)
import Data.Either as DE (rights, lefts)

import Data.Aeson
import Control.Applicative
import Control.Monad
import qualified Data.ByteString.Lazy as BSL 
import qualified Data.ByteString.Lazy.Char8 as C -- for packing, could potentially be avoided with a different read function
import GHC.Generics

confPath = "/etc/csprg/gen.conf"

-- Reads in the file, processes the reports and prints out the policy suggestion
main :: IO ()
main =
  do
    mconf <- readConf confPath -- reads conf
    conf 
      <-
        case mconf of
          Right conf -> return conf
          Left msg -> 
              error $ "Error in parsing config: " ++ msg
    handle <- openFile (inpath conf) ReadMode
    lines <- hGetLines handle -- Read in the reports
    hClose handle
    let (errs, policy) = linesToPolicy conf lines --Process the reports into a policy
    mapM putStrLn errs -- Print out all occuring warnings/errors
    handle <- openFile (outpath conf) WriteMode -- Write to file
    hPutStr handle policy
    hClose handle
    putStrLn $ "Policy generation successful. The generated policy is:"
    putStrLn $ policy

-------------------------------------------------------------------------
--HELPERS SECTION--
-------------------------------------------------------------------------


-- Get lines from one Handle until EOF
hGetLines :: Handle -> IO [String]
hGetLines handle =
  do
    eof <- hIsEOF handle
    if eof
      then
        return []
      else
        do
          line <- hGetLine handle
          lines <- hGetLines handle
          return (line:lines)

-------------------------------------------------------------------------
--CONFIG SECTION--
-------------------------------------------------------------------------

-- An entry of the black- or whitelist
data Entry = Entry { directive :: String, value :: String } deriving (Generic, Show, Eq)
data Conf = Conf { self :: String, inpath :: String, outpath :: String,  whitelist :: [Entry], blacklist :: [Entry]} deriving (Generic, Show)

instance FromJSON Entry
instance ToJSON Entry
instance FromJSON Conf
instance ToJSON Conf

readConf :: String -> IO (Either String Conf)
readConf cpath =
  (eitherDecode <$> BSL.readFile cpath)

-------------------------------------------------------------------------
--ACTUAL STUFF SECTION--
-------------------------------------------------------------------------

{-
	This is where the magic happens - somewhat likes this:
	0.	Create a map from Whitelist
	1. 	Map a reduction on every input line, reducing it to Either String (String, String) (and already do replacement of keywords and blacklistcheck)
	2.	Fold the successfull lines into a Map Directivename [Value] starting with Whitelist, doing dup-removal, grouping
	3.	Fold the unsuccessfull lines into [Errormsg]
	4.	Turn the map into a policy
	5.	Return ([Errormsg], Policy)
-}

data OuterReport = OuterReport
  { cspReport :: Report } deriving (Eq, Show)
instance FromJSON OuterReport where
  parseJSON (Object x) = OuterReport <$> x.: "csp-report"
  parseJSON _ = fail "Exptected an Object"
instance ToJSON OuterReport where
  toJSON oReport = object
    [ "csp-report" .= cspReport oReport ]

data Report = Report 
  { blockedUri :: String
  , effectiveDirective :: String
  } deriving (Eq, Show)
instance FromJSON Report where
  parseJSON (Object x) = Report <$> x .: "blocked-uri" <*> x.: "effective-directive"
  parseJSON _ = fail "Expected an Object"
instance ToJSON Report where
  toJSON report = object
    [ "blocked-uri" .= blockedUri report
    , "effective-directiv" .= effectiveDirective report
    ]

type Errormsg = String
type Policy = String
type Line = String
linesToPolicy :: Conf -> [Line] -> ([Errormsg], Policy)
linesToPolicy conf lines = 
  let
    wl = foldr (\entry wl -> insertWith ((++)) (directive entry) [(value entry)] wl) DMS.empty (whitelist conf)
    mappedLines = map (parseLine conf) lines
  in
    (lefts mappedLines, mapToPolicy . buildPolicy wl . rights $ mappedLines)

type DName =  String
type DValue = String
parseLine :: Conf -> Line -> Either Errormsg (DName, DValue)
parseLine conf line = 
  let
    -- Remove the JSON and reduce to important fields
    reduced = case (eitherDecode :: C.ByteString -> Either String OuterReport) (C.pack line) of
      Left e -> Left e
      Right or -> let r = cspReport or in Right (effectiveDirective r, blockedUri r)
    replaced = case reduced of -- Replaced occurences of self, eval and inline
      Left _ -> Left ("Could not parse line: " ++ line)
      Right d@(dname, dvalue) -> case dvalue of
        "inline" -> Right (dname, "'unsafe-inline'")
        "eval" -> Right (dname, "'unsafe-eval'")
        otherwise -> if isPrefixOf (self conf) dvalue then Right (dname, "'self'") else Right d
    bled = case replaced of -- Blacklistchecks
      Left err -> Left err
      Right d@(dname, dvalue) -> case elem (Entry {directive = dname, value = dvalue}) (blacklist conf) of
        True -> Left ("Line matches blacklist entry: " ++ line)
        False -> Right d
  in
    bled

-- Builds a map of the policy from the given Whitelist and reports.
buildPolicy :: Map DName [DValue] -> [(DName, DValue)] -> Map DName [DValue]
buildPolicy wl lines =
  let
    lineMap = fromListWith (++) . map (\(k,a) -> (k, [a])) $ lines
  in
    DMS.map nub . unionWith (++) wl $ lineMap

-- Flattens the Map into a policy
mapToPolicy :: Map DName [DValue] -> Policy
mapToPolicy = concat . map (\(dname, dvalue) -> dname ++ " " ++ (concat . intersperse " " $ dvalue) ++ "; ") . toList

-- lookup in the list generate from JSON
lookupJS :: (Eq a, Show a) => a -> [(a, b)] -> Either String b
lookupJS v xs = 
  case Prelude.lookup v xs of
    Just x -> Right x
    Nothing -> Left ("Key " ++ show v ++ " not found.")
