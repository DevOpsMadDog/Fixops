# ALdeci-enhanced PentAGI Image
# Merges ALdeci's advanced vulnerability management features into PentAGI
FROM vxcontrol/pentagi:latest

# Switch to root to modify files
USER root

# Copy custom frontend files
COPY fe/ /opt/pentagi/fe/

# Copy ALdeci enhancement script
COPY aldeci-inject.js /opt/pentagi/fe/assets/aldeci-inject.js

# Create modified index.html with ALdeci branding and injection
RUN sed -i 's/<title>PentAGI<\/title>/<title>ALdeci - Algorithmic Vulnerability Management<\/title>/' /opt/pentagi/fe/index.html && \
    sed -i 's/<\/head>/<script type="module" src="\/assets\/aldeci-inject.js"><\/script><\/head>/' /opt/pentagi/fe/index.html

# Ensure correct permissions
RUN chown -R pentagi:pentagi /opt/pentagi/fe

# Switch back to pentagi user
USER pentagi

# Expose ports
EXPOSE 8443

# Use existing entrypoint
ENTRYPOINT ["/opt/pentagi/bin/entrypoint.sh"]
