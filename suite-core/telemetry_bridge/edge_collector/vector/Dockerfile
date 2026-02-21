FROM timberio/vector:0.35.0-debian

# Copy configuration
COPY vector.toml /etc/vector/vector.toml

# Set environment variables from overlay (will be overridden at runtime)
ENV INPUT_PATH=/logs/app.log
ENV FLUSH_INTERVAL=30

CMD ["vector", "--config", "/etc/vector/vector.toml"]
