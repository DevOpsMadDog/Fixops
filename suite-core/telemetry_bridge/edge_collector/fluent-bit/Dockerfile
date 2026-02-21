FROM fluent/fluent-bit:2.2

# Copy configuration files
COPY fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY parsers.conf /fluent-bit/etc/parsers.conf
COPY aggregate.lua /fluent-bit/etc/aggregate.lua

# Set environment variables from overlay (will be overridden at runtime)
ENV INPUT_PATH=/var/log/waf/*.log
ENV AGGREGATION_INTERVAL=60
ENV RETRY_LIMIT=5

CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
