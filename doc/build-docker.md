DOCKER BUILD NOTES
==================
These notes describe how to build Neurai binaries inside Docker containers and how to export them to the host machine. The workflow mirrors the style used in the other build documents.

Overview
---------------------
- Install a recent Docker Engine (24.x or newer recommended).
- Clone the Neurai source tree locally so the Docker build context includes the repository files.
- The Dockerfiles live under `doc/docker/` and currently target Linux (`Dockerfile-Linux64-bin`) and Windows (`Dockerfile-Win64-bin`) artifacts.
- The images compile Neurai inside `/root/Neurai` and leave the build products in that directory. The container keeps running (`tail -f /dev/null`) so you can copy files out after the build completes.

Building Linux x86_64 binaries
---------------------
1. From the repository root, build the image:
   ```bash
docker build -f doc/docker/Dockerfile-Linux64-bin -t neurai-linux64-build .
```
2. Create a stopped container from that image:
   ```bash
docker create --name neurai-linux64-out neurai-linux64-build
```
3. Copy the artifacts to the host. The most common binaries live in `/root/Neurai/src/`:
   ```bash
mkdir -p build-out/linux64
# Core daemons and CLI tools
docker cp neurai-linux64-out:/root/Neurai/src/neuraid build-out/linux64/
docker cp neurai-linux64-out:/root/Neurai/src/neurai-cli build-out/linux64/
docker cp neurai-linux64-out:/root/Neurai/src/neurai-tx build-out/linux64/
# Optional GUI wallet (built when Qt dependencies succeed)
docker cp neurai-linux64-out:/root/Neurai/src/qt/neurai-qt build-out/linux64/ || true
```
   If you prefer to archive everything, copy the full directory instead:
   ```bash
docker cp neurai-linux64-out:/root/Neurai/src/. build-out/linux64/
```
4. (Optional) Collect the pre-built dependency tree (useful for redistributable packages):
   ```bash
docker cp neurai-linux64-out:/root/Neurai/depends/x86_64-pc-linux-gnu/. build-out/linux64/depends/
```
5. Remove the temporary container when finished:
   ```bash
docker rm neurai-linux64-out
```

Building Windows x86_64 binaries
---------------------
1. Build the cross-compilation image:
   ```bash
docker build -f doc/docker/Dockerfile-Win64-bin -t neurai-win64-build .
```
2. Create a container from the image:
   ```bash
docker create --name neurai-win64-out neurai-win64-build
```
3. Copy the Windows artifacts to the host. Executables are placed under `/root/Neurai/src/`:
   ```bash
mkdir -p build-out/win64
# Daemon and command-line tools
docker cp neurai-win64-out:/root/Neurai/src/neuraid.exe build-out/win64/ || true
docker cp neurai-win64-out:/root/Neurai/src/neurai-cli.exe build-out/win64/ || true
docker cp neurai-win64-out:/root/Neurai/src/neurai-tx.exe build-out/win64/ || true
# GUI wallet (if Qt build succeeded)
docker cp neurai-win64-out:/root/Neurai/src/qt/neurai-qt.exe build-out/win64/ || true
# Copy the entire directory if you plan to package everything
docker cp neurai-win64-out:/root/Neurai/src/. build-out/win64/
```
4. Grab the cross-compiled dependency outputs if needed:
   ```bash
docker cp neurai-win64-out:/root/Neurai/depends/x86_64-w64-mingw32/. build-out/win64/depends/
```
5. Remove the container after extracting the files:
   ```bash
docker rm neurai-win64-out
```

Inspecting or customizing builds
---------------------
- Start an interactive shell to inspect the workspace:
  ```bash
docker run --rm -it neurai-linux64-build /bin/bash
```
  From there you can rerun `make`, adjust `-j` flags, or tweak configuration options.
- To rebuild with local source modifications, edit the repository and re-run `docker build`. Docker’s layer cache will reuse previously completed steps when possible.
- Adjust the Dockerfiles if you need different configure flags (for example, enabling tests or indexing).

Extracting artifacts with running containers
---------------------
If you prefer to keep the container running while copying files, replace the `docker create` step with:
```bash
docker run -d --name neurai-linux64-out neurai-linux64-build
docker cp neurai-linux64-out:/root/Neurai/src/neuraid build-out/linux64/
...
docker stop neurai-linux64-out && docker rm neurai-linux64-out
```

Cleanup
---------------------
- Remove build images when finished:
  ```bash
docker rmi neurai-linux64-build neurai-win64-build
```
- Delete the `build-out/` directory once artifacts are archived.

Troubleshooting
---------------------
- Use `docker logs <container>` to review the build output if a layer fails.
- Ensure the host has enough RAM and disk space; the images compile the full dependency tree, which can take several gigabytes.
- If Docker is running on Windows or macOS, make sure file sharing is enabled for the drive that hosts the repository, otherwise the `docker build` context may be empty.

With these steps you can produce reproducible Linux and Windows binaries without installing the complete toolchain on your host.
