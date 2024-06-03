{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}

module Main where

import Control.Monad (when)
import Data.ByteString.Lazy qualified as BSL
import Data.Foldable (for_, toList)
import Data.Map (Map)
import Data.Map qualified as Map
import Data.Time (getCurrentTime)
import Distribution.Compat.NonEmptySet (NonEmptySet)
import Distribution.Package
import Distribution.PackageDescription
  ( Benchmark (..),
    ComponentName (..),
    ConfVar,
    Executable (..),
    ForeignLib (..),
    GenericPackageDescription (..),
    Library (..),
    LibraryName,
    TestSuite (..),
    foldCondTree,
    mapTreeData,
    prettyLibraryNameComponent,
  )
import Distribution.PackageDescription.Parsec (parseGenericPackageDescriptionMaybe)
import Distribution.Pretty (prettyShow)
import Distribution.Types.CondTree (CondTree (..))
import Distribution.Types.Lens qualified as L
import Distribution.Version (VersionRange, intersectVersionRanges, unionVersionRanges)
import Hackage.Security.Client
  ( CacheLayout (..),
    Directory (..),
    IndexCallbacks (..),
    IndexEntry (..),
    IndexFile (..),
    KeyThreshold (..),
    bootstrap,
    checkForUpdates,
    hackageIndexLayout,
    hackageRepoLayout,
    requiresBootstrap,
    uncheckClientErrors,
    withIndex,
  )
import Hackage.Security.Client.Repository (Repository)
import Hackage.Security.Client.Repository.Cache (Cache (..))
import Hackage.Security.Client.Repository.HttpLib.HTTP (withClient)
import Hackage.Security.Client.Repository.Remote
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some
import Lens.Micro
import Network.URI (parseURI)

cabalCacheLayout :: CacheLayout
cabalCacheLayout =
  CacheLayout
    { cacheLayoutRoot = rootPath $ fragment "root.json",
      cacheLayoutTimestamp = rootPath $ fragment "timestamp.json",
      cacheLayoutSnapshot = rootPath $ fragment "snapshot.json",
      cacheLayoutMirrors = rootPath $ fragment "mirrors.json",
      cacheLayoutIndexTar = rootPath $ fragment "01-index.tar",
      cacheLayoutIndexIdx = rootPath $ fragment "01-index.tar.idx",
      cacheLayoutIndexTarGz = rootPath $ fragment "01-index.tar.gz"
    }

main :: IO ()
main = do
  let logger = putStrLn . pretty
  root <- makeAbsolute (fromFilePath "_cache")
  let cache = Cache {cacheRoot = root, cacheLayout = cabalCacheLayout}
  let Just uri = parseURI "http://hackage.haskell.org"

  -- Download the Hackage index (and keep it updated)
  withClient $ \_browser httpLib -> withRepository
    httpLib
    [uri]
    defaultRepoOpts
    cache
    hackageRepoLayout
    hackageIndexLayout
    logger
    $ \repository ->
      uncheckClientErrors $ do
        rb <- requiresBootstrap repository
        when rb $ bootstrap repository [] (KeyThreshold 0)

        -- NOTE: Uncomment the following line to check for updates each time
        -- getCurrentTime >>= \now -> checkForUpdates repository (Just now) >>= print

        foldIndex repository processCabalFile

processCabalFile :: PackageId -> BSL.LazyByteString -> IO ()
processCabalFile pkgId cabalFile = do
  case parseGenericPackageDescriptionMaybe (BSL.toStrict cabalFile) of
    Nothing ->
      putStrLn $ "Fail to parse the cabal file for " ++ prettyShow pkgId
    Just gpd ->
      let dependencyMaps = map (foldCondTree e u mergeInclusive mergeExclusive) (toListOf allCondTrees gpd)
       in for_ dependencyMaps $ \dependencyMap ->
            -- Example
            for_ (Map.toList dependencyMap) $ \((cn, pn, ln), vr) ->
              putStrLn $
                unwords
                  [ prettyShow pkgId,
                    prettyShow cn,
                    prettyShow pn,
                    show $ prettyLibraryNameComponent ln,
                    prettyShow vr
                  ]

-- | A data type to represent dependencies extrated from a package description.
--
-- In the analised package description; 'ComponentName' depends on 'LibraryName'
-- in 'PackageName' constrained by 'VersionRange'
type DependencyMap = Map (ComponentName, PackageName, LibraryName) VersionRange

toDepMap :: ComponentName -> [Dependency] -> DependencyMap
toDepMap cn deps = Map.fromList [((cn, p, ln), vr) | Dependency p vr cs <- deps, ln <- toList cs]

fromDepMap :: Map PackageName (VersionRange, NonEmptySet LibraryName) -> [Dependency]
fromDepMap m = [Dependency p vr cs | (p, (vr, cs)) <- Map.toList m]

-- | This defines how to dependency maps are merged when two paths might co-exist.
mergeInclusive :: DependencyMap -> DependencyMap -> DependencyMap
mergeInclusive = Map.unionWith intersectVersionRanges

-- | This defines how to dependency maps are merged when two paths are dijoined.
mergeExclusive :: DependencyMap -> DependencyMap -> DependencyMap
mergeExclusive = Map.unionWith unionVersionRanges

-- | The singleton dependecy map
u :: ([Dependency], ComponentName) -> DependencyMap
u (deps, cname) = toDepMap cname deps

-- | The empty dependency map
e :: DependencyMap
e = mempty

--
-- Utility functions
--

-- | Apply a function to all the cabal files in the index.
foldIndex :: Repository down -> (PackageId -> BSL.ByteString -> IO ()) -> IO ()
foldIndex repository k =
  withIndex repository $ \IndexCallbacks {indexLookupEntry, indexDirectory} ->
    let go entry = do
          (Some indexEntry, maybeNextEntry) <- indexLookupEntry entry
          case indexEntryPathParsed indexEntry of
            Just (IndexPkgCabal pkgId) ->
              k pkgId (indexEntryContent indexEntry)
            _otherwise ->
              pure ()
          for_ maybeNextEntry go
     in go (directoryFirst indexDirectory)

-- | Extract all the conditional trees from a package description, data
-- at the leaves of the tree is replaced by just the name of the component.
allCondTrees :: SimpleFold GenericPackageDescription (CondTree ConfVar [Dependency] ComponentName)
allCondTrees =
  (L.condLibrary . traverse . to onlyComponentName)
    <> (L.condSubLibraries . traverse . _2 . to onlyComponentName)
    <> (L.condForeignLibs . traverse . _2 . to onlyComponentName)
    <> (L.condExecutables . traverse . _2 . to onlyComponentName)
    <> (L.condTestSuites . traverse . _2 . to onlyComponentName)
    <> (L.condBenchmarks . traverse . _2 . to onlyComponentName)
  where
    onlyComponentName :: (HasComponentName a) => CondTree v c a -> CondTree v c ComponentName
    onlyComponentName = mapTreeData componentName

-- | A type class to get the component name of a component (blah)
class HasComponentName a where
  componentName :: a -> ComponentName

instance HasComponentName Library where
  componentName = CLibName . libName

instance HasComponentName ForeignLib where
  componentName = CFLibName . foreignLibName

instance HasComponentName Executable where
  componentName = CExeName . exeName

instance HasComponentName TestSuite where
  componentName = CTestName . testName

instance HasComponentName Benchmark where
  componentName = CBenchName . benchmarkName
