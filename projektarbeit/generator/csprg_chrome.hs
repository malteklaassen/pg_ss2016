{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}

module Main where
import System.IO as SIO (Handle, IOMode (ReadMode, WriteMode), hIsEOF, hClose, hGetLine, hPutStr, openFile)

import Data.Map.Strict as DMS (Map, insertWith, fromListWith, unionWith, toList)
import qualified Data.Map.Strict as DMS (map, empty)

import Data.List as DL (isPrefixOf, nub, intersperse)
import Data.Either as DE (rights, lefts)

import Data.Aeson
import qualified Data.ByteString.Lazy as BSL 
import qualified Data.ByteString.Lazy.Char8 as C -- for packing, could potentially be avoided with a different read function
import GHC.Generics (Generic)

-- Hardcoded path of the Config file
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

-- Data type for Entries in Black- or Whitelist
data Entry = Entry { directive :: String, value :: String } deriving (Generic, Show, Eq)
-- Data type for the configuration
data Conf = Conf { self :: [String], inpath :: String, outpath :: String,  whitelist :: [Entry], blacklist :: [Entry]} deriving (Generic, Show)

instance FromJSON Entry
instance FromJSON Conf

-- Reading in the configuration file from the give location & parsing the JSON. The parser is automatically generated through the Conf data type and the DeriveGenerics Language Extension
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


-- Data types for parsing the reports. Unluckily we need multiple levels here as the actual reports are wrapped in an JSON object that only has a single field.
data OuterReport = OuterReport
  { cspReport :: Report } deriving (Eq, Show)
-- Generic derivation doesnt help us here as - is a reserved character in Haskell so we can't give our fields the correct names. Instead we need to defines the FromJSON instace by hand (for those fields).
instance FromJSON OuterReport where
  parseJSON (Object x) = OuterReport <$> x.: "csp-report"
  parseJSON _ = fail "Exptected an Object"

data Report = Report 
  { blockedUri :: String
  , effectiveDirective :: String
  } deriving (Eq, Show)
instance FromJSON Report where
  parseJSON (Object x) = Report <$> x .: "blocked-uri" <*> x.: "effective-directive"
  parseJSON _ = fail "Expected an Object"

-- Types for easier reading of the Function types
type Errormsg = String
type Policy = String
type Line = String


linesToPolicy :: Conf -> [Line] -> ([Errormsg], Policy)
linesToPolicy conf lines = 
  let
    -- Preprocessing the whitelist into a Map which will later be used by buildPolicy function
    wl = foldr (\entry wl -> insertWith ((++)) (directive entry) [(value entry)] wl) DMS.empty (whitelist conf)
    -- Preprocessing the lines
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
    -- Replace with keywords
    replaced = case reduced of -- Replaced occurences of self, eval and inline
      Left _ -> Left ("Could not parse line: " ++ line)
      Right d@(dname, dvalue) -> case dvalue of
        "inline" -> Right (dname, "'unsafe-inline'")
        "eval" -> Right (dname, "'unsafe-eval'")
        otherwise -> if any (\s -> isPrefixOf s dvalue) . self $ conf then Right (dname, "'self'") else Right d
    bled = case replaced of -- Blacklistchecks
      Left err -> Left err
      Right d@(dname, dvalue) -> case elem (Entry {directive = dname, value = dvalue}) (blacklist conf) || elem (Entry {directive = dname, value = "*"}) (blacklist conf)  of
        True -> Left ("Line matches blacklist entry: " ++ line)
        False -> Right d
  in
    bled

-- Builds a map of the policy from the given Whitelist and reports.
buildPolicy :: Map DName [DValue] -> [(DName, DValue)] -> Map DName [DValue]
buildPolicy wl =
  DMS.map nub . unionWith (++) wl . fromListWith (++) . map (\(k,a) -> (k, [a]))

-- Flattens the Map into a policy
mapToPolicy :: Map DName [DValue] -> Policy
mapToPolicy = concat . map (\(dname, dvalue) -> dname ++ " " ++ (concat . intersperse " " $ dvalue) ++ "; ") . toList

