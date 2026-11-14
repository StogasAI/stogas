# Install the stogas CLI on Windows:
#
#   irm https://raw.githubusercontent.com/StogasAI/stogas/main/install.ps1 | iex
#
# $env:STOGAS_VERSION installs that release instead of the newest, and $env:STOGAS_INSTALL_DIR
# installs into that directory instead of %LOCALAPPDATA%\Programs\stogas, which this script adds to
# your user PATH. The archive must match the SHA-256 that the release manifest lists for it.
& {
	$ErrorActionPreference = 'Stop'
	$ProgressPreference = 'SilentlyContinue'
	$repository = 'StogasAI/stogas'
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

	$version = "$env:STOGAS_VERSION".TrimStart('v')
	if (-not $version) {
		# The newest full release, or before the first one, the newest preview.
		try {
			$version = (Invoke-RestMethod "https://api.github.com/repos/$repository/releases/latest").tag_name
		} catch {
			$version = (Invoke-RestMethod "https://api.github.com/repos/$repository/releases?per_page=1")[0].tag_name
		}
		if (-not $version) { throw "Cannot find a release of $repository" }
		$version = $version.TrimStart('v')
	}
	$architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
		'X64' { 'amd64' }
		'Arm64' { 'arm64' }
		default { throw "No release for $_ processors" }
	}
	$name = "stogas-cli-v$version-windows-$architecture"
	$base = "https://github.com/$repository/releases/download/v$version"
	$directory = if ($env:STOGAS_INSTALL_DIR) { $env:STOGAS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\stogas' }

	$work = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
	New-Item -ItemType Directory -Path $work | Out-Null
	try {
		Invoke-WebRequest "$base/$name.zip" -OutFile (Join-Path $work "$name.zip") -UseBasicParsing
		Invoke-WebRequest "$base/release-manifest.json" -OutFile (Join-Path $work 'release-manifest.json') -UseBasicParsing
		$manifest = Get-Content -Raw (Join-Path $work 'release-manifest.json') | ConvertFrom-Json
		$expected = ($manifest.artifacts | Where-Object { $_.name -eq "$name.zip" }).sha256
		if (-not $expected) { throw "The manifest of release v$version lists no $name.zip" }
		if ((Get-FileHash -Algorithm SHA256 (Join-Path $work "$name.zip")).Hash -ne $expected) {
			throw "$name.zip does not match its SHA-256 in the release manifest"
		}
		Expand-Archive (Join-Path $work "$name.zip") -DestinationPath $work
		New-Item -ItemType Directory -Force -Path $directory | Out-Null
		Copy-Item (Join-Path $work "$name\stogas.exe") (Join-Path $directory 'stogas.exe') -Force
	} finally {
		Remove-Item -Recurse -Force $work
	}
	Write-Output "Installed stogas $version in $directory"

	$path = [Environment]::GetEnvironmentVariable('Path', 'User')
	if (($path -split ';') -notcontains $directory) {
		[Environment]::SetEnvironmentVariable('Path', (@($path, $directory) | Where-Object { $_ }) -join ';', 'User')
		$env:Path = "$env:Path;$directory"
		Write-Output "Added $directory to your user PATH. Open a new terminal to run stogas."
	}
}
