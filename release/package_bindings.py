"""Package language adapters around the exact native build artifacts."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from artifacts import digest, unpack, write_json

MAVEN = "maven:3.9.11-eclipse-temurin-17@sha256:e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82"
DOTNET = "mcr.microsoft.com/dotnet/sdk:10.0@sha256:35d40304542c8689331f8cab17c65926cdf48fe711e289321d71924b230a7d29"
RUBY = "ruby:3.4.9-bookworm@sha256:83c7e4fb558ab6c73fbc89bbdd577dbe882fd8c9b9fdf562ccd009785153d8e1"
PACKER = "ghcr.io/rust-cross/cargo-xwin:0.23.1@sha256:9856b895265d4966f212228ba64802cf89337e2a2a537aa2533c1b8784cbc81b"


def container(image, source, arguments, epoch, environment=()):
    subprocess.run([
        "docker", "run", "--rm", "--init", "--memory", "4g", "--cpus", "4",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,source={source},target=/build", "--workdir", "/build",
        "--env", f"SOURCE_DATE_EPOCH={epoch}", "--env", "TZ=UTC",
        "--env", "MAVEN_OPTS=-Duser.home=/build", "--env", "MAVEN_CONFIG=/build/.m2",
        "--env", "DOTNET_CLI_HOME=/build/.dotnet", "--env", "GEM_HOME=/build/.gem",
        *[part for entry in environment for part in ("--env", entry)],
        image, *arguments,
    ], check=True)


def package(build_directory):
    destination = build_directory / "packages"
    if destination.exists():
        raise ValueError("Package output already exists")
    with tempfile.TemporaryDirectory(prefix=".packages-", dir=build_directory) as temporary:
        output = Path(temporary) / "packages"
        output.mkdir()
        assemble(build_directory, output)
        output.rename(destination)


def assemble(build_directory, output):
    metadata = json.loads((build_directory / "build.json").read_text())
    source = build_directory / "source"
    from release import source_digest
    if metadata["source"]["sha256"] != source_digest(source):
        raise ValueError("Build source has changed")
    version = json.loads((source / "package.json").read_text())["version"]
    targets = json.loads((source / "release/targets.json").read_text())["targets"]
    platforms = metadata["platforms"]
    epoch = metadata["source"]["epoch"]
    with tempfile.TemporaryDirectory(prefix="stogas-bindings-") as temporary:
        work = Path(temporary)
        shutil.copytree(source / "bindings", work / "bindings")
        shutil.copytree(source / "include", work / "include")
        shutil.copyfile(source / "LICENSE", work / "LICENSE")
        shutil.copyfile(source / "package.json", work / "package.json")
        shutil.copytree(source / "release", work / "release")
        shutil.copytree(source / "go", work / "go")
        shutil.copyfile(source / "LICENSE", work / "go/LICENSE")
        spec = importlib.util.spec_from_file_location("stage_native", source / "scripts/stage-native-bindings.py")
        stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stage)
        for platform in [*platforms, *metadata["bundles"]]:
            shard = build_directory / platform
            description = json.loads((shard / f"{platform}.json").read_text())
            if description["environment"] != "prod" or description["platform"] != platform:
                raise ValueError("Native build identity mismatch")
            apple = platform == "apple" or targets.get(platform, {}).get("os") in {"macos", "ios"}
            for artifact in description["artifacts"]:
                path = shard / artifact["name"]
                if path.name != artifact["name"] or not path.is_file() or path.is_symlink() or path.stat().st_size != artifact["size"] or digest(path) != artifact["sha256"]:
                    raise ValueError("Native artifact differs from its recorded bytes")
                if apple:
                    # Apple compilation needs Xcode, but final archive bytes use
                    # the same pinned Python/zlib as every other release host.
                    with tempfile.TemporaryDirectory(prefix="apple-archive-", dir=work) as temporary:
                        tree = Path(temporary) / "tree"
                        unpack(path, tree)
                        pack_archive(work, tree, output / path.name, epoch)
                else:
                    shutil.copyfile(path, output / path.name)
            if platform == "portable":
                continue
            if platform == "apple":
                unpack(shard / f"stogas-xcframework-v{version}.zip", work / "apple")
                shutil.copytree(work / "apple/CStogas.xcframework", work / "bindings/swift/CStogas.xcframework")
                continue
            target = targets[platform]
            name = f"stogas-v{version}-{platform}"
            suffix = "zip" if target["os"] == "windows" else "tar.gz"
            unpack(shard / f"{name}.{suffix}", work / platform)
            native = work / platform / name
            stage.stage(platform, native, work / "bindings", version, apple_swift=False)
            if "go" in target["packages"]:
                archive = native / ("go/libstogas_verifier_ffi.a" if target["os"] == "windows" else "libstogas_verifier_ffi.a")
                destination = work / "go/native" / platform
                destination.mkdir(parents=True)
                shutil.copyfile(archive, destination / archive.name)
            if "ruby" in target:
                shutil.copyfile(source / "LICENSE", work / "bindings/ruby/LICENSE")
                gem = f"stogas-{version.replace('-', '.')}-{target['ruby']}.gem"
                container(RUBY, work, ["gem", "-C", "bindings/ruby", "build", "stogas.gemspec", "--output", f"/build/{gem}"], epoch, [f"STOGAS_RUBY_PLATFORM={target['ruby']}"])
                shutil.copyfile(work / gem, output / gem)
        packages = {kind for platform in platforms if platform != "portable" for kind in targets[platform]["packages"]}
        if "java" in packages:
            container(MAVEN, work, ["mvn", "-B", "-ntp", "-f", "bindings/java/pom.xml", f"-Dproject.build.outputTimestamp={epoch}", "-DskipTests", "package"], epoch)
            jar = work / "bindings/java/target" / f"stogas-{version}.jar"
            shutil.copyfile(jar, output / jar.name)
            for classifier in ("sources", "javadoc"):
                jar = work / "bindings/java/target" / f"stogas-{version}-{classifier}.jar"
                shutil.copyfile(jar, output / jar.name)
            shutil.copyfile(source / "bindings/java/pom.xml", output / f"stogas-{version}.pom")
        if "android" in packages:
            identity = work / ".android-image"
            subprocess.run(["docker", "build", "--iidfile", str(identity), "--file", str(source / "release/android.Dockerfile"), str(source / "release")], check=True)
            container(identity.read_text().strip(), work, ["gradle", "--no-daemon", "--project-dir", "bindings/android", "publishReleasePublicationToSdkRepository"], epoch)
            repository = work / "bindings/android/build/repository/ai/stogas/stogas-android" / version
            # Gradle normalizes its archives and publishes their exact digests in
            # module metadata. Preserve that complete publication unchanged.
            for suffix in (".aar", ".pom", ".module", "-sources.jar", "-javadoc.jar"):
                artifact = repository / f"stogas-android-{version}{suffix}"
                shutil.copyfile(artifact, output / artifact.name)
        if "dotnet" in packages:
            container(DOTNET, work, ["dotnet", "pack", "bindings/dotnet/Stogas", "--output", "/build/nuget", "-p:ContinuousIntegrationBuild=true", "-p:Deterministic=true", "-p:PathMap=/build=/stogas"], epoch)
            for archive in (work / "nuget").glob("*.nupkg"):
                tree = work / "nuget-unpacked"
                unpack(archive, tree)
                pack_archive(work, tree, output / archive.name, epoch)
        if "swift" in packages:
            swift = work / "bindings/swift"
            if any(targets[name]["os"] in {"macos", "ios"} for name in platforms if name != "portable") and not (swift / "CStogas.xcframework").is_dir():
                raise ValueError("Apple Swift packaging requires build --platform apple")
            shutil.copyfile(source / "LICENSE", swift / "LICENSE")
            pack_archive(work, swift, output / f"stogas-swift-v{version}.tar.gz", epoch, "Stogas")
        if "go" in packages:
            # The Go proxy accepts at most 500 MiB both compressed and expanded.
            # Keep the complete self-contained module below that public limit.
            from artifacts import regular_files
            if sum(path.stat().st_size for path in regular_files(work / "go")) > 500 * 1024**2:
                raise ValueError("The Go module exceeds the Go proxy's expanded archive limit")
            pack_archive(work, work / "go", output / f"stogas-go-v{version}.tar.gz", epoch, "go")
        shutil.copytree(source, work / "source")
        pack_archive(work, work / "source", output / f"stogas-source-v{version}.tar.gz", epoch, f"stogas-v{version}")
        write_json(output / "release-manifest.json", {
            "schema": "stogas.sdk-release.v1", "environment": "prod", "version": version,
            "source": metadata["source"], "targets": platforms,
            "artifacts": [{"name": path.name, "sha256": digest(path), "size": path.stat().st_size} for path in sorted(output.iterdir())],
        })
    print(f"Packaged {len(platforms)} native targets; qualification is required before approval")


def pack_archive(work, source, destination, epoch, prefix=""):
    """Use one pinned Python/zlib pair on every build host."""
    relative = source.relative_to(work).as_posix()
    temporary = work / destination.name
    container(PACKER, work, ["python3", "release/artifacts.py", "tar.gz" if destination.name.endswith(".tar.gz") else "zip", relative, destination.name, "--epoch", str(epoch), "--prefix", prefix], epoch)
    shutil.copyfile(temporary, destination)
