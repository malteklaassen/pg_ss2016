{-# LANGUAGE DeriveGeneric #-}

module Main where
-- in some versions: Data.JSON etc
import Text.JSON
import Text.JSON.String
import Text.JSON.Generic
import System.IO
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.List hiding (lookup)
import Data.Either (rights, lefts)
-- in some versions: Network.URI
import Text.URI
import Prelude hiding (lookup)
import qualified Prelude (lookup)

import Data.Aeson
import Control.Applicative
import Control.Monad
import qualified Data.ByteString.Lazy as BSL
import GHC.Generics

{-
Two example reports as sent by Google Chrome with Policy "script-src 'none'; media-src 'none'; img-src 'none'; report-uri /read.php".
Due to the field "effective-directive" the usage of Chrome should be easier - even though Chrome seems to not always report the correct original-directive but a simplified equivalent one. Unluckily this makes it incompatible with Firefox, as Firefox reports the violated directive from the actual original policy. 
{"csp-report":
	{"document-uri":"http://localhost/ssl.html"
	,"referrer":""
	,"violated-directive":"img-src 'none'"
	,"effective-directive":"img-src"
	,"original-policy":"script-src 'none'; media-src 'none'; img-src 'none'; report-uri /read.php"
	,"blocked-uri":"https://pbs.twimg.com"
	,"status-code":200
	}
}

{"csp-report":
	{"document-uri":"http://localhost/malte/gm.html"
	,"referrer":""
	,"violated-directive":"default-src 'none'"
	,"effective-directive":"style-src"
	,"original-policy":"default-src 'none'; report-uri /read.php"
	,"blocked-uri":"https://fonts.googleapis.com"
	,"source-file":"https://maps.googleapis.com"
	,"line-number":42
	,"column-number":402
	,"status-code":200}}
-}

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

type Errormsg = String
type Policy = String
type Line = String
linesToPolicy :: Conf -> [Line] -> ([Errormsg], Policy)
linesToPolicy conf lines = 
  let
    wl = foldr (\entry wl -> Map.insertWith ((++)) (directive entry) [(value entry)] wl) Map.empty (whitelist conf)
    mappedLines = map (parseLine conf) lines
  in
    (lefts mappedLines, mapToPolicy . buildPolicy wl . rights $ mappedLines)

type DName =  String
type DValue = String
parseLine :: Conf -> Line -> Either Errormsg (DName, DValue)
parseLine conf line = 
  let
    reduced = do  -- Remove the JSON and reduce to important fields
      inner <- lineToInnerObject line
      reduceObjectToImportantFields inner
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
    lineMap = Map.fromListWith (++) . map (\(k,a) -> (k, [a])) $ lines
  in
    Map.map nub . Map.unionWith (++) wl $ lineMap

-- Flattens the Map into a policy
mapToPolicy :: Map DName [DValue] -> Policy
mapToPolicy = concat . map (\(dname, dvalue) -> dname ++ " " ++ (concat . intersperse " " $ dvalue) ++ "; ") . Map.toList

-- We have an outer and an inner JSON-Object. The outer one is of no relevance for us but still has to be stripped
lineToInnerObject :: String -> Either String (JSObject JSValue)
lineToInnerObject line =
  do
    outerObject <-
      case runGetJSON readJSObject line of
        Right (JSObject outerObject) -> return outerObject
        otherwise -> Left "Could not parse outer Object"
    innerObject <- 
      case (map snd) . filter (\(s, _) -> s == "csp-report") . fromJSObject $ outerObject of
        [JSObject innerObject] -> return $ innerObject -- There may be EXACTALY ONE OBJECT
        otherwise -> Left "Could not parse inner Object"
    return innerObject -- semantically not necessary, but nicer formatting

type RelevantData = (String, String) -- I just always wanted to name a Data Type "RelevantData", holds the directive and value extracted from JSON

-- Maybe RelevantData is just a nice thing to have in code
reduceObjectToImportantFields :: JSObject JSValue -> Either String RelevantData
reduceObjectToImportantFields obj =
  do
    uri <- lookup "blocked-uri" . fromJSObject $ obj
    directive <- lookup "effective-directive" . fromJSObject $ obj
    case (uri, directive) of
      (JSString uri_, JSString directive_) -> return (fromJSString directive_, fromJSString uri_)
      otherwise -> Left "uri or directive could not be parsed to a string"

-- lookup in the list generate from JSON
lookup :: (Eq a, Show a) => a -> [(a, b)] -> Either String b
lookup v xs = 
  case Prelude.lookup v xs of
    Just x -> Right x
    Nothing -> Left ("Key " ++ show v ++ " not found.")


