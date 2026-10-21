# Python environment of the C7 reference checks (contrib/privacypool/privacy-c7/run-tests.sh).
FROM python:3.13.16-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends libsodium23 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir cryptography==50.0.2
