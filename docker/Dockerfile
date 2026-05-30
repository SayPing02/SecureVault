# Build and test environment for SecureVault
# Can't run the GUI in docker, but we can compile and run tests

FROM rust:1.83-bookworm

# system libs needed by tauri to compile
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebkit2gtk-4.1-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libssl-dev \
    build-essential \
    curl \
    wget \
    file \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# node.js for frontend tooling
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt

WORKDIR /app

COPY src-tauri/Cargo.toml ./src-tauri/Cargo.toml
COPY package.json ./package.json
RUN cd src-tauri && cargo fetch || true

COPY . .
RUN npm install

CMD ["cargo", "test", "--manifest-path", "src-tauri/Cargo.toml"]
