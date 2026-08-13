DOCKER BUILD NOTES
==================
These notes describe how to build Neurai binaries inside Docker containers and how to export them to the host machine. The workflow mirrors the style used in the other build documents.

Overview
---------------------
- Install a recent Docker Engine (24.x or newer recommended).
- Clone the Neurai source tree locally so the Docker build context includes the repository files.
- Binary Dockerfiles live under `doc/docker/bin/` and target Linux (`Dockerfile-Linux64-bin`) and Windows (`Dockerfile-Win64-bin`) artifacts.
- The BuildKit `artifacts` stage exports the requested binaries directly to `build-out/`; no temporary container is needed.

Building Linux x86_64 binaries
---------------------
1. From the repository root, build the image:
   ```bash
docker build -f doc/docker/bin/Dockerfile-Linux64-bin --target artifacts --output type=local,dest=build-out/linux64 .
```
2. Docker exports the artifacts directly to `build-out/linux64/`: `neuraid`, `neurai-cli`, and `neurai-qt`.

Building Windows x86_64 binaries
---------------------
1. Build the cross-compilation image:
   ```bash
docker build -f doc/docker/bin/Dockerfile-Win64-bin --target artifacts --output type=local,dest=build-out/win64 .
```
2. Docker exports the artifacts directly to `build-out/win64/`: `neuraid.exe`, `neurai-cli.exe`, and `neurai-qt.exe`.

Inspecting or customizing builds
---------------------
- To inspect the Linux build stage interactively, build that stage as an image:
  ```bash
docker build --target build -t neurai-linux64-build -f doc/docker/bin/Dockerfile-Linux64-bin .
docker run --rm -it neurai-linux64-build /bin/bash
```
  From there you can rerun `make`, adjust `-j` flags, or tweak configuration options.
- To rebuild with local source modifications, edit the repository and re-run `docker build`. Docker’s layer cache will reuse previously completed steps when possible.
- Adjust the Dockerfiles if you need different configure flags (for example, enabling tests or indexing).

Cleanup
---------------------
- Remove build images when finished:
  ```bash
docker rmi neurai-linux64-build neurai-win64-build
```
- Delete the `build-out/` directory once artifacts are archived.

Troubleshooting
---------------------
- Run the `docker build` command without redirected output to review a failed layer.
- Ensure the host has enough RAM and disk space; the images compile the full dependency tree, which can take several gigabytes.
- If Docker is running on Windows or macOS, make sure file sharing is enabled for the drive that hosts the repository, otherwise the `docker build` context may be empty.

With these steps you can produce reproducible Linux and Windows binaries without installing the complete toolchain on your host.
