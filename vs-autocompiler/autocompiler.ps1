param (
    [string]$sln,
    [string]$out = "G:/out",
    [string]$SetupScriptPath
)
# TODO: Add force-dotnet or force-native

function CopyNoOverwrite {
    param (
        [string]$src,
        [string]$dst
    )

    # TODO: Strip extension to add suffix and then readd it (instead of just adding .exe ontop)
    If (Test-Path $dst) {
        $i = 0
        While (Test-Path $dst) {
            $i += 1
            $dst = "$dst-$i.exe"
        }
    } Else {
        New-Item -ItemType File -Path $dst -Force
    }

    Copy-Item -Path $src -Destination $dst -Force
}

function Git-Clean {
    git clean -fdx  # Force, include directories
    git reset --hard
}

function Upgrade-VCProj {

}

function Create-Initial-Directories {
    $ProjectName = (Get-Item -Path ".\").Name
    $outDir = "$out/$ProjectName/"
    mkdir $outDir
}

function Existing-Executables-Sha256 {
    $executables = Get-ChildItem -Include *.exe, *.dll -Recurse $pwd
    $hashes = @()
    ForEach ($executable in $executables)
    {
        $sha = (Get-FileHash -Path $executable.FullName).hash
        $hashes += $sha
    }
    return $hashes
}

function Move-Compiled {
    param (
        [string]$outSuffix,
        [string]$ExistingHashes
    )
    $ProjectName = (Get-Item -Path ".\").Name
    $outDir = "$out/$ProjectName/$ProjectName$outSuffix/"

    $executables = Get-ChildItem -Include *.exe, *.dll -Recurse $pwd

    # Remove executables not created by our compilation
    $filtered_executables = @()
    ForEach ($executable in $executables) {
        $sha = (Get-FileHash -Path $executable.FullName).hash
        If (!$ExistingHashes.Contains($sha)) {
            $filtered_executables += $executable
        }
    }
    $executables = $filtered_executables

    # Move compiled executables to destination directory
    if($executables.Length -gt 0){
        Remove-Item $outDir -Recurse -Force > $null
        mkdir $outDir > $null

        ForEach ($executable in $executables)
        {
            $outFile = $outDir + $executable.Name
            CopyNoOverwrite -src $executable.FullName -dst $outFile > $null
        }
        return $true
    } Else {
        Write-Information "Failed to build $ProjectName$outSuffix"
        return $false
    }
}

function Find-Git-Checkpoints {
    # Each checkpoint is a month
    $gitHist = (git log --format="%ai`t%H`t%an`t%ae`t%s") | ConvertFrom-Csv -Delimiter "`t" -Header ("Date", "CommitId", "Author", "Email", "Subject")
    ForEach ($hist in $gitHist) {
        $YearMonth = $hist.Date.Substring(0, 7)
        $hist | Add-Member -NotePropertyName YearMonth -NotePropertyValue $YearMonth
    }
    $GitCommits = ($gitHist | Sort-Object -Property YearMonth -Unique)
    
    return $GitCommits
}

function Reset-Compiler-Env {
    [Environment]::SetEnvironmentVariable("LIB", "")
    [Environment]::SetEnvironmentVariable("INCLUDE", "")
    [Environment]::SetEnvironmentVariable("VSINSTALLDIR", "")
    [Environment]::SetEnvironmentVariable("VSCMD_VER", "")
    [Environment]::SetEnvironmentVariable("VSCMD_ARG_HOST_ARCH", "")
    [Environment]::SetEnvironmentVariable("VSCMD_ARG_TGT_ARCH", "")
    [Environment]::SetEnvironmentVariable("VisualStudioVersion", "")
    [Environment]::SetEnvironmentVariable("VS140COMNTOOLS", "")
    [Environment]::SetEnvironmentVariable("VS150COMNTOOLS", "")
    [Environment]::SetEnvironmentVariable("VS160COMNTOOLS", "")
    [Environment]::SetEnvironmentVariable("VCToolsVersion", "")
    [Environment]::SetEnvironmentVariable("VCToolsRedistDir", "")
    [Environment]::SetEnvironmentVariable("VCToolsInstallDir", "")
    [Environment]::SetEnvironmentVariable("VCINSTALLDIR", "")
    [Environment]::SetEnvironmentVariable("VCIDEInstallDir", "")
}

$COMPILERS_NUM = 6

function Setup-Compiler-ByIndex {
    param (
        [int]$i
    )

    $byIndex = @(
        "v100",
        "v120",
        "v140",
        "v140_xp",
        "v141",
        "v142"
    )
    
    $configs = @{
        "v100" = @{
            "Env" = @{"VCTargetsPath" = "C:\Program Files (x86)\MSBuild\Microsoft.Cpp\v4.0\"}
            "MSBuild" = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
            "Toolset_Version" = "v100"
        }
        "v120" = @{
            "Env" = @{"VCTargetsPath" = "C:\Program Files (x86)\MSBuild\Microsoft.Cpp\v4.0\v120\"}
            "MSBuild" = "C:\Program Files `(x86`)\MSBuild\12.0\Bin\MSBuild.exe"
            "Toolset_Version" = "v120"
        }
        "v140" = @{
            "Env" = @{"VCTargetsPath" = "C:\Program Files (x86)\MSBuild\Microsoft.Cpp\v4.0\v140\"}
            "MSBuild" = "C:\Program Files `(x86`)\MSBuild\14.0\Bin\MSBuild.exe"
            "Toolset_Version" = "v140"
        }
        "v140_xp" = @{
            "Env" = @{"VCTargetsPath" = "C:\Program Files (x86)\MSBuild\Microsoft.Cpp\v4.0\v140\"}
            "MSBuild" = "C:\Program Files `(x86`)\MSBuild\14.0\Bin\MSBuild.exe"
            "Toolset_Version" = "v140_xp"
        }
        "v141" = @{
            "Env" = @{"VCTargetsPath" = ""}
            "MSBuild" = "C:\Program Files `(x86`)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"
            "Toolset_Version" = "v141"
        }
        "v142" = @{
            "Env" = @{"VCTargetsPath" = ""}
            "MSBuild" = "C:\Program Files `(x86`)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
            "Toolset_Version" = "v142"
        }
    }
    #$extra_env.v140.initenv = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

    $config = $configs[$byIndex[$i]]
    Reset-Compiler-Env
    foreach ($k in $config.Env.Keys) {
        [Environment]::SetEnvironmentVariable($k, $config.Env[$k])
    }
    return $config
}

function Bootstrap-Compiler-Options {
    $globaloptions = @{
        "WholeProgramOptimization" = @("true", "false")
    }

    $projFiles = Get-ChildItem -Include *.vcxproj -Recurse $pwd

    ForEach ($projFile in $projFiles)
    {
        [xml]$xmldata = Get-Content $projFile.FullName

        [System.Xml.XmlNamespaceManager]$ns = $xmldata.NameTable
        $ns.AddNamespace("Any", $xmldata.DocumentElement.NamespaceURI)

        $xmldata.SelectNodes('//Any:WindowsTargetPlatformVersion', $ns) | ForEach-Object { $_.ParentNode.RemoveChild($_) }
        $xmldata.SelectNodes('//Any:PrecompiledHeader', $ns) | ForEach-Object { $_.InnerText = "NotUsing" }
        $xmldata.SelectNodes('//Any:GenerateDebugInformation', $ns) | ForEach-Object { $_.ParentNode.RemoveChild($_) }
        $xmldata.SelectNodes('//Any:EnableEnhancedInstructionSet', $ns) | ForEach-Object { $_.ParentNode.RemoveChild($_) }
        # TODO: Add legacy_stdio_definitions.lib to AdditionalDependencies
        $ForceLinker = $xmldata.CreateElement("ForceFileOutput", $xmldata.DocumentElement.NamespaceURI)
        $ForceLinker.InnerText = "UndefinedSymbolOnly"
        $xmldata.SelectNodes('//Any:Link', $ns) | ForEach-Object { $xmldata.CreateElement("ForceFileOutput"); $_.AppendChild($ForceLinker) }

        $xmldata.Save($projFile.FullName)
    }
}

function Optional-Setup-Script {

}

function Optional-Cleanup-Script {

}

function Compile-Job-Native {
    param (
        [string]$arch,
        [string]$exec,
        [string]$sln,
        [string]$toolset_version,
        [string]$Suffix
    )
    Git-Clean > $null
    $CLOptions = Bootstrap-Compiler-Options

    $ExistingHashes = Existing-Executables-Sha256

    # Compile
    Write-Information "Building for $arch with $toolset_version with cmd: $exec `"$sln`" /m /p:Configuration=Release /p:Platform=`"$arch`" /p:PlatformToolset=$toolset_version"
    $proc = Start-Process -Passthru -NoNewWindow -FilePath $exec -ArgumentList "`"$sln`" /m /p:Configuration=Release /p:Platform=`"$arch`" /p:PlatformToolset=$toolset_version"
    $proc.WaitForExit()

    # Find and move compiled executables
    Write-Information "Finding executables generated for $arch $toolset_version"
    $success = Move-Compiled -ExistingHashes $ExistingHashes -outSuffix "-$toolset_version-$arch$Suffix"
    return $success
}

function Compile-Job-Dotnet {
    param(
        [string]$sdkversion,
        [string]$exec,
        [string]$sln,
        [string]$Suffix
    )
    Git-Clean > $null
    nuget restore $sln > $null
    $ExistingHashes = Existing-Executables-Sha256

    # Compile
    Write-Information "Building for with $sdkversion with cmd: $exec `"$sln`" /m /p:Configuration=Release /p:TargetFramework=$sdkversion /p:AllowUnsafeBlocks=true"
    $proc = Start-Process -Passthru -NoNewWindow -FilePath $exec -ArgumentList "`"$sln`" /m /p:Configuration=Release /p:TargetFramework=$sdkversion /p:AllowUnsafeBlocks=true"
    $proc.WaitForExit()

    # Find and move compiled executables
    Write-Information "Finding executables generated for $sdkversion"
    $success = Move-Compiled -ExistingHashes $ExistingHashes -outSuffix "-$sdkversion$Suffix"
    return $success
}

function Get-Project-Type {
    $csprojs = Get-ChildItem -Include *.csproj -Recurse $pwd
    If($csprojs.Length -gt 0) {
        return "dotnet"
    }
    return "native"
}

function Batch-Compile {
    param (
        [string]$Suffix
    )

    If(-Not (Test-Path $sln)) {
        Write-Information "Couldn't find $sln with suffix $suffix"
        return $false
    }
    $projectType = Get-Project-Type
    If($projectType -eq "native") {
        for ($i=0; $i -lt $COMPILERS_NUM; $i++) {
            $config = Setup-Compiler-ByIndex -i $i
            $compiler = $config.MSBuild
            $toolset_version = $config.Toolset_Version
            $exec = @"
"$compiler"
"@

            # Build for x86
            $success = Compile-Job-Native -arch "x86" -exec $exec -sln $sln -toolset_version $toolset_version -Suffix $Suffix

            If($success -eq $false) {
                Write-Information "x86 build failed, trying Win32!"
                Compile-Job-Native -arch "Win32" -exec $exec -sln $sln -toolset_version $toolset_version -Suffix $Suffix
            }
            # Build for x64
            Compile-Job-Native -arch "x64" -exec $exec -sln $sln -toolset_version $toolset_version -Suffix $Suffix

            # Try compiling for 'Any CPU'
            Compile-Job-Native -arch "Any CPU" -exec $exec -sln $sln -toolset_version $toolset_version -Suffix $Suffix
        }
    }
    If($projectType -eq "dotnet"){
        $sdkversions = @("net35", "net45", "netstandard2.0")
        $exec = "C:\Program Files `(x86`)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
        ForEach($sdkversion in $sdkversions){
            Compile-Job-Dotnet -sdkversion $sdkversion -exec $exec -sln $sln -Suffix $suffix
        }
    }
    
    return $true
}

function Load-Setup-Script {
    If( Test-Path $SetupScriptPath ) {
        Import-Module -Name $SetupScriptPath
    }
}

function Find-Sln {
    $slns = Get-ChildItem *.sln
    if($slns.Count -eq 0) {
        echo "Couldn't find SLN file!"
        exit 1
    }
    if($slns.Count -gt 1) {
        echo "More than 1 SLN file found!"
        exit 1
    }
    return $slns[0].FullName
}

function Main{
    # Determine whether to start git mode: traverse bymonthly commits to compile additional code
    git status
    $gitExists = $LASTEXITCODE
    Write-Information "Starting!"

    Create-Initial-Directories
    if ([string]::IsNullOrEmpty($sln)) {
        $sln = Find-Sln
    }

    If ($gitExists -eq 0) {
        git checkout master
        git pull
        $GitCommits = Find-Git-Checkpoints
        [array]::Reverse($GitCommits)
        ForEach($GitCommit in $GitCommits) {
            git reset --hard $GitCommit.CommitId
            $success = (Batch-Compile -Suffix "-$($GitCommit.YearMonth)")
            If(-Not $success){
                break
            }
        }
    } Else {
        Batch-Compile -Suffix ""
    }
}

$InformationPreference = "Continue"
Main

