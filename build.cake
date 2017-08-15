#addin nuget:?package=Cake.Git
#tool "nuget:?package=NUnit.ConsoleRunner"

var target = Argument("target", "Default");

//////////////////////////////////////////////////////////////////////
// VARIABLES
//////////////////////////////////////////////////////////////////////

string semVersion = EnvironmentVariable("BUILD_VERSION") ?? "1.0.0-DEV";
string version = string.Join(".", semVersion.Split(new string []{".","-"}, StringSplitOptions.RemoveEmptyEntries).Take(3));

const string BUILD_CONFIG = "Release";
const string SOLUTION_PATH = "./Encryption.Hybrid.sln";
var artifactsDir = "./artifacts/";

//////////////////////////////////////////////////////////////////////
// PATCH 
//////////////////////////////////////////////////////////////////////

Task("Patch")
    .Does(() => {
        var file = "./SolutionInfo.cs";

        CreateAssemblyInfo(file, new AssemblyInfoSettings {
            Version = version,
            FileVersion = version,
            InformationalVersion = semVersion,
            });        
    });

///////////////////////////////////////////////////////////////////////////////
// PREPARE
///////////////////////////////////////////////////////////////////////////////

Task("Clean")
    .Does(() => {
		var directoriesToClean = GetDirectories("./**/bin/")
                                    .Union(GetDirectories(artifactsDir));
	
		CleanDirectories(directoriesToClean);
    });

Task("NugetRestore")
    .IsDependentOn("Clean")
    .Does(() => 
    {
        NuGetRestore(SOLUTION_PATH);
    });

///////////////////////////////////////////////////////////////////////////////
// BUILD
///////////////////////////////////////////////////////////////////////////////

Task("Build")
    .IsDependentOn("Patch")
    .IsDependentOn("NugetRestore")
    .Does(() =>
    {
		MSBuild(SOLUTION_PATH, configurator => configurator
                    .SetConfiguration(BUILD_CONFIG)
                    .SetVerbosity(Verbosity.Minimal)                    
                    .SetMSBuildPlatform(MSBuildPlatform.x64)
                    .SetPlatformTarget(PlatformTarget.MSIL));
    });

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

Task("Test")
    .IsDependentOn("Build")
    .Does(() =>
    {
		var testAssemblies = GetFiles(string.Format("./tests/**/bin/{0}/*Tests.dll", BUILD_CONFIG));

        NUnit3(testAssemblies, new NUnit3Settings {
            NoResults = false
        });
    });

///////////////////////////////////////////////////////////////////////////////
// Package
///////////////////////////////////////////////////////////////////////////////

Task("Pack")
    .IsDependentOn("Test")
    .Does(() =>
    {
		var nuspecFiles = GetFiles("*/**/*.csproj");
        
        var nuGetPackSettings = new NuGetPackSettings {
                                    Symbols                 = false,
                                    NoPackageAnalysis       = true,
                                    OutputDirectory         = "./nuget",
                                    ArgumentCustomization = args => args.Append("-Prop Configuration=" + BUILD_CONFIG)
                                 };

        foreach(var nuspecFile in nuspecFiles)
        {
            NuGetPack(nuspecFile.FullPath, nuGetPackSettings);
        }
    });

Task("Default")
    .IsDependentOn("Pack");

RunTarget(target);