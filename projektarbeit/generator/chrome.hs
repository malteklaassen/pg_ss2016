module Main where
-- in some versions: Data.JSON etc
import Text.JSON
import Text.JSON.String
import Text.JSON.Generic
import System.IO
import qualified Data.Map.Strict as Map
import Data.List
-- in some versions: Network.URI
import Text.URI


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

-- Reads in the file, processes the reports and prints out the policy suggestion
main :: IO ()
main =
  do
    conf <- readConf "gen.conf" -- reads conf
    handle <- openFile (path conf) ReadMode
    lines <- hGetLines handle -- Input
    hClose handle
    case linesToPolicy conf lines of --Processing
      Just policy -> putStrLn policy --Output
      Nothing -> error "Couldn't create policy"

-------------------------------------------------------------------------
--CONFIG SECTION--
-------------------------------------------------------------------------

data Conf = Conf { self :: String, path :: String, inline :: [String]}

readConf :: String -> IO Conf
readConf cpath =
  do
    chandle <- openFile cpath ReadMode
    lines <- hGetLines chandle
    let line = concat lines
    hClose chandle
    case parseConf line of
      Just conf -> return conf
      Nothing -> error "Couldn't parse config file"

parseConf :: String -> Maybe Conf
parseConf line = 
  do
    obj <- 
      case runGetJSON readJSObject line of
        Right (JSObject obj) -> return obj
        otherwise -> fail "Couldn't parse to JSON Object"
    jvpath <- lookup "path" . fromJSObject $ obj
    jvself <- lookup "self" . fromJSObject $ obj
    javinline <- lookup "inline" . fromJSObject $ obj
    vpath <- case jvpath of {JSString vpath -> return . fromJSString $ vpath; otherwise -> Nothing }
    vself <- case jvself of {JSString vself -> return . fromJSString $ vself; otherwise -> Nothing }
    avinline <- case javinline of {JSArray avinline -> return avinline; otherwise -> Nothing }
    vinline <-
      mapM
        ( 
          \jvinline
            ->
              case jvinline of
                JSString vinline -> return . fromJSString $ vinline
                otherwise -> Nothing
        )
      avinline
    return Conf {self = vself, path = vpath, inline = vinline}
        
      

-------------------------------------------------------------------------
--ACTUAL STUFF SECTION--
-------------------------------------------------------------------------

linesToPolicy :: Conf -> [String] -> Maybe String
linesToPolicy conf lines =
  do -- Maybe-Monad for easier processing
    reduced <- reduce lines -- reduction on important Fields
    let grouped = groupFirst . map (\(x,y) -> (y,x)) $ reduced -- grouping on directive-value
    let selfed = map (\(key, values) -> (key, map (\value -> if isPrefixOf (self conf) value then "'self'" else value ) $ values )) $ grouped -- duplicate removal, adding of self, unsafe-inline. Possible todo: List of allowed/forbidden inlines
    inlined 
      <- 
        mapM 
          (
            \(key, values) 
              -> 
                do
                  ivalues 
                    <- 
                      mapM
                        (
                          \value
                            ->
                              if value == "inline"
                                then
                                  if elem key (inline conf)
                                    then
                                      return "'unsafe-inline'"
                                    else
                                      fail "illegal inline"
                                else
                                  return value
                        )
                        values
                  return (key, ivalues)
          ) 
          selfed
    return . concat . intersperse "; " . map (\(key, values) -> key ++ " " ++ (concat . intersperse " " $ values)) . map (\(key, values) -> (key, nub values)) $ inlined 
       

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

-- JSON reduction
-- All wrapped in Maybe-Monads for easier error-handling
reduce :: [String] -> Maybe [(String, String)]
reduce = 
  mapM 
    ( 
      \line 
        -> 
          do 
            inner <- lineToInnerObject line -- line -> JSON
            reduceObjectToImportantFields inner-- JSON -> (String, String)
    )

-- We have an outer and an inner JSON-Object. The outer one is of no relevance for us but still has to be stripped
lineToInnerObject :: String -> Maybe (JSObject JSValue)
lineToInnerObject line =
  do
    outerObject <-
      case runGetJSON readJSObject line of
        Right (JSObject outerObject) -> return outerObject
        otherwise -> fail "Could not parse outer Object"
    innerObject <- 
      case (map snd) . filter (\(s, _) -> s == "csp-report") . fromJSObject $ outerObject of
        [JSObject innerObject] -> return $ innerObject -- There may be EXACTALY ONE OBJECT
        otherwise -> fail "Could not parse inner Object"
    return innerObject -- semantically not necessary, but nicer formatting

type RelevantData = (String, String) -- I just always wanted to name a Data Type "RelevantData", holds the directive and value extracted from JSON

-- Maybe RelevantData is just a nice thing to have in code
reduceObjectToImportantFields :: JSObject JSValue -> Maybe RelevantData
reduceObjectToImportantFields obj =
  do
    uri <- lookup "blocked-uri" . fromJSObject $ obj
    directive <- lookup "effective-directive" . fromJSObject $ obj
    case (uri, directive) of
      (JSString uri_, JSString directive_) -> return (fromJSString uri_, fromJSString directive_)
      otherwise -> fail "Not a String"
     
-- Grouping on first argument, based on a map. I'm really not happy with this solution but it does it's job.
groupFirst :: Ord a => [(a, String)] -> [(a, [String])]
-- 1. Create a map
-- 2. Collect the keys
-- 3. concat
groupFirst xs = 
  case 
    mapM -- Map.lookup is [...] -> Maybe a, so delegate the Maybe to the outside of the list were we strip it. As Nothing cant happen anyway we could also use fromJust.
      (
        \key
          -> 
            case Map.lookup key (makeMap xs) of
              Just string -> return (key, string)
              otherwise -> error "This cant happen//1"
      ) 
      (allKeys $ xs) 
  of
    Just x -> x
    Nothing -> error "This cant happen//2"

-- Generate a Map key -> [value]. We DONT do duplicate reduction here, that is done after further processing. If you want some duplicate reduction done earlier, you should probably already do it even earlier than this.
makeMap :: Ord a => [(a, String)] -> Map.Map a [String]
makeMap = 
  foldr 
    (
      \(key,value) oldmap 
        -> 
          Map.insertWith 
            (
              ++
              {-\s1 s2 
                -> 
                  if elem value s2 then s2 else value:s2-}
            ) 
            key 
            [value] 
            oldmap
    ) 
    Map.empty

-- Returns all the keys for the map.
allKeys :: Eq a => [(a, String)] -> [a]
allKeys = nub . map fst
