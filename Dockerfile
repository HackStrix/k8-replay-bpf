FROM debian:bookworm-slim

# Install procps to gain access to 'pidof' and 'kill' required for Tilt live-update script
RUN apt-get update && \
    apt-get install -y procps libc6 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./bin/mirroring /app/mirroring

# When starting normally (e.g. without Tilt live update)
CMD ["/app/mirroring"]
