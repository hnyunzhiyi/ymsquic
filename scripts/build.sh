#!/bin/bash


#.SYNOPSIS
#This script provides helpers for building msquic.

#.PARAMETER Config
#    The debug or release configuration to build for.

#.PARAMETER Arch
#    The CPU architecture to build for.

#.PARAMETER Platform
#    Specify which platform to build for

#.PARAMETER Tls
#    The TLS library to use.

#.PARAMETER ToolchainFile
#    Toolchain file to use (if cross)

#.PARAMETER DisableLogs
#    Disables log collection.

#.PARAMETER SanitizeAddress
#    Enables address sanitizer.

#.PARAMETER DisableTools
#    Don't build the tools directory.

#.PARAMETER DisableTest
#    Don't build the test directory.

#.PARAMETER DisablePerf
#    Don't build the perf directory.

#.PARAMETER Clean
#    Deletes all previous build and configuration.

#.PARAMETER InstallOutput
#    Installs the build output to the current machine.

#.PARAMETER Parallel
#    Enables CMake to build in parallel, where possible.

#.PARAMETER DynamicCRT
#    Builds msquic with dynamic C runtime (Windows-only).

#.PARAMETER PGO
#    Builds msquic with profile guided optimization support (Windows-only).

#.PARAMETER Generator
#    Specifies a specific cmake generator (Only supported on unix)

#.PARAMETER SkipPdbAltPath
#    Skip setting PDBALTPATH into built binaries on Windows. Without this flag, the PDB must be in the same directory as the DLL or EXE.

#.PARAMETER SkipSourceLink
#    Skip generating sourcelink and inserting it into the PDB.

#.PARAMETER Clang
#    Build with Clang if available

#.PARAMETER UpdateClog
#    Build allowing clog to update the sidecar.

#.PARAMETER ConfigureOnly
#    Run configuration only.

#.PARAMETER CI
#    Build is occuring from CI

#.EXAMPLE
#    build.ps1

#.EXAMPLE
#    build.ps1 -Config Release

Config="Debug"
Arch="x64"
Platform="linux"
Tls=""
ToolchainFile=""
#DisableLogs=false
SanitizeAddress=false
DisableTools=false
DisableTest=false
DisablePerf=false
Parallel=-1
DynamicCRT=false
PGO=false
Generator=""
SkipPdbAltPath=false
SkipSourceLink=false
Clang=false
UpdateClog=false
ConfigureOnly=false
CI=false
IsLinux=true
Arguments=""
Clean=false
Value=""
bool=true
#Set-StrictMode -Version 'Latest'

for Parameter in "$@"
do
    if [[ "$bool" = "true" ]]; then
        Value=$Parameter;
    fi

    if [[ "${Value}" = "-Config" ]]; then
        if [[ "$bool" = "true" ]]; then
	    bool=false
	    continue
	else
	    if [ -z "${Parameter}" ] || [[ "${Parameter}" = "Release" ]] || [[ "${Parameter}" = "Debug" ]]; then
	        bool=true
	    else
		echo "The argument" ${Parameter} "does not belong to the set Release,Debug"
		exit
	    fi
    fi
    elif [[ "${Value}" = "-Arch" ]]; then
        if [[ "$bool" = "true" ]]; then
	    bool=false
	    continue
	else
	    if [[ "${Parameter}" = "" ]] || [[ "${Parameter}" = "x64" ]] || [[ "${Parameter}" = "arm" ]] || [[ "${Parameter}" = "arm64" ]]; then
	        bool=true
		Arch=${Parameter}
	    else
		echo "The argument" ${Parameter} "does not belong to the x64,arm,arm64"
		exit
	    fi
    fi
    elif [[ "${Value}" = "-Tls" ]]; then
        if [[ "$bool" = "true" ]]; then
	    bool=false
	    continue
	else
	    if [[ "${Parameter}" = "" ]] || [[ "${Parameter}" = "stub" ]] || [[ "${Parameter}" = "openssl" ]] || [[ "${Parameter}" = "mitls" ]]; then
	        Tls=${Parameter}
		bool=true
	    else
		echo "The argument" ${Parameter} "does not belong to the set openssl,stub,mitls"
		exit
	    fi
    fi
    elif [[ "${Value}" = "-Platform" ]]; then
        if [[ "$bool" = "true" ]]; then
	    bool=false
	    continue
	else
	    if [[ "${Parameter}" = "windows" ]] || [[ "${Parameter}" = "linux" ]]; then
	        Platform=${Parameter}
		bool=true
	    else
		echo "The argument" ${Parameter} "does not belong to the set windows,linux"
		exit
	    fi
        fi
    elif [[ "${Value}" = "-ToolchainFile" ]]; then
        if [[ "$bool" = "true" ]]; then
	    bool=false
	    continue
	else
	    ToolchainFile=${Parameter}
	    bool=true
	fi
    elif [[ "${Value}" = "-Parallel" ]]; then
        if [ "$bool" = true ]; then
	    bool=false
	    continue
	else
	    Parallel=${Parameter}
	    bool=true
	fi
    elif [[ "${Value}" = "-Generator" ]]; then
        if [ "$bool" = true ]; then
	    bool=false
	    continue
	else
	    if [ -n "${Parameter}" ]; then 
	        Generator=${Parameter}
		bool=true
	    fi
	fi	
    elif [[ "${Value}" = "-Clean" ]]; then
        Clean=true
	bool=true
    elif [[ "${Value}" = "-DisableLogs" ]]; then
	DisableLogs=true
	bool=true
		
    elif [[ "${Value}" = "-DisableTools" ]]; then
	DisableTools=true
	bool=true
    elif [[ "${Value}" = "-DisableTest" ]]; then
	DisableTest=true
	bool=true
    elif [[ "${Value}" = "-DisablePerf" ]]; then
	DisablePerf=true
	bool=true
    elif [[ "${Value}" = "-SkipPdbAltPath" ]]; then
	SkipPdbAltPath=true
	bool=true
    elif [[ "${Value}" = "-PGO" ]]; then
	PGO=true
	bool=true
    elif [[ "${Value}" = "-DynamicCRT" ]]; then
	DynamicCRT=true
	bool=true
    elif [[ "${Value}" = "-Clang" ]]; then
	Clang=true
	bool=true
    elif [[ "${Value}" = "-CI" ]]; then
	CI=true
	bool=true
    elif [[ "${Value}" = "-UpdateClog" ]]; then
	UpdateClog=true
	bool=true
    elif [[ "${Value}" = "-ConfigureOnly" ]]; then
	ConfigureOnly=true
	bool=true
    elif [[ "${Value}" = "-SkipSourceLink" ]]; then
	SkipSourceLink=true
	bool=true
    elif [[ "${Value}" = "-SanitizeAddress" ]]; then
	SanitizeAddress=true
	bool=true
    else 
	echo "no useful parameter"
    fi
done

if [ -z "${Generator}" ];then 
    if [ $IsLinux ];then 
        Generator="Ninja"
    else 
        Generator="Unix Makefiles"
    fi
fi


# Root directory of the project.
RootDir=`cd \`dirname $0\`\/..; pwd`

# Important directory paths.
BaseArtifactsDir="$RootDir/artifacts"
BaseBuildDir="$RootDir/build"
ArtifactsDir="$BaseArtifactsDir/bin/$Platform"
BuildDir="$BaseBuildDir/$Platform"

ArtifactsDir="$ArtifactsDir/$Arch"_"$Config"_"$Tls"
BuildDir="$BuildDir/$Arch"_"$Tls"

echo "BaseBuildDir:$BaseBuildDir"

if [[ "$Clean" = "true" ]];then
    # Delete old build/config directories.

    if [ -d "$ArtifactsDir" ];then
	rm -r $ArtifactsDir
    fi 
    
    if [ -d "$BuildDir" ];then
	rm -r $BuildDir
    fi
    
fi 

# Initialize directories needed for building.
if [ ! -d "$BaseArtifactsDir" ];then 
	mkdir -p $BaseArtifactsDir
fi

if [ ! -d "$BuildDir" ];then
     mkdir -p $BuildDir
fi 

if [[ "$Clang" = "true" ]];then 
    $env:CC = 'clang'
    $env:CXX = 'clang++'
fi

function CMake_Execute() {
   cd $BuildDir
   export version=$(which cmake3)
   if [ -n "${version}" ];then
	compiler=$(echo __GNUC__|$version --version)
	MAJOR=`echo ${compiler} | awk  -F 'version '  '{print $NF}' | awk -F '.'  '{print $1}'`
	MINOR=`echo ${compiler} | awk  -F 'version '  '{print $NF}' | awk -F '.'  '{print $2}'`
	if [[ "$MAJOR" -ge 3 ]];then
	    if [[ "$MAJOR" -eq 3 ]] && [[ "$MINOR" -lt 5 ]];then
	        cmake $Arguments
	    else
		cmake3 $Arguments
	    fi
        fi
   else
    	cmake $Arguments
   fi
}

# Uses cmake to generate the build configuration files.
function CMake_Generate() {
    Arguments="-g"
    Arguments+=" '$Generator'"
    Arguments+=" -DQUIC_TLS="$Tls
    Arguments+=" -DQUIC_OUTPUT_DIR="$ArtifactsDir
	
    if [[ "$SanitizeAddress" = "true" ]];then
        Arguments+=" -DQUIC_ENABLE_SANITIZERS=on"
    fi
    if [[ "$DisableTools" = "true" ]];then
        Arguments+=" -DQUIC_BUILD_TOOLS=off"
    fi 
    if [[ "$DisableTest" = "true" ]];then
        Arguments+=" -DQUIC_BUILD_TEST=off"
    fi
    if [[ "$DisablePerf" = "true" ]];then
        Arguments+=" -DQUIC_BUILD_PERF=off"
    fi 
    if [ $IsLinux ];then
        Arguments+=" -DCMAKE_BUILD_TYPE="$Config
    fi
    if [[ "$DynamicCRT" = "true" ]];then
        Arguments+=" -DQUIC_STATIC_LINK_CRT=off"
    fi
    if [[ "$PGO" = "true" ]];then
        Arguments+=" -DQUIC_PGO=on"
    fi

    if [[ "${Platform}" = "uwp" ]];then
        Arguments+=" -DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10 -DQUIC_UWP_BUILD=on -DQUIC_STATIC_LINK_CRT=Off"
    fi 
    if [ -n "${ToolchainFile}" ];then
        Arguments+=" ""-DCMAKE_TOOLCHAIN_FILE="$ToolchainFile""""
    fi 
    if [[ "$SkipPdbAltPath" = "true" ]];then
        Arguments+=" -DQUIC_PDBALTPATH=OFF"
    fi 
    if [[ "$SkipSourceLink" = "true" ]];then
        Arguments+=" -DQUIC_SOURCE_LINK=OFF"
    fi 
    if [[ "$CI" = "true" ]];then 
        Arguments+=" -DQUIC_CI=ON"
        Arguments+=" -DQUIC_VER_BUILD_ID=$env:BUILD_BUILDID"
        Arguments+=" -DQUIC_VER_SUFFIX=-official"
    fi

    Arguments+=" ../../.."
    CMake_Execute $Arguments
}

# Uses cmake to generate the build configuration files.
function CMake_Build() {
    Arguments="--build ."
    if [[ $Parallel -ge 0 ]];then 
        Arguments+=" --parallel $($Parallel)"
    elif [[ $Parallel -eq 0 ]];then
        Arguments+=" --parallel"
    fi 

    Arguments+=" -- VERBOSE=1"
    CMake_Execute $Arguments
}

##############################################################
#                     Main Execution                         #
##############################################################
if [[ "$UpdateClog" = "true" ]];then 
    $env:CLOG_DEVELOPMENT_MODE=1
fi

# Generate the build files.
CMake_Generate

if  [[ "$ConfigureOnly" = "false" ]];then
    CMake_Build
fi

if [[ "$UpdateClog" = "true" ]];then
    $env:CLOG_DEVELOPMENT_MODE=0
fi

