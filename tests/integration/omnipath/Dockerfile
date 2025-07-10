FROM alpine:latest

# Use busybox's built-in HTTP client instead of installing wget
# Create a script to send requests to google.com using busybox
RUN echo '#!/bin/sh' > /request_script.sh && \
    echo 'echo "Starting requests to google.com..."' >> /request_script.sh && \
    echo 'for i in $(seq 1 10); do' >> /request_script.sh && \
    echo '  echo "Request $i/10 to google.com"' >> /request_script.sh && \
    echo '  busybox wget -q --spider https://google.com' >> /request_script.sh && \
    echo '  if [ $? -eq 0 ]; then' >> /request_script.sh && \
    echo '    echo "Request $i successful"' >> /request_script.sh && \
    echo '  else' >> /request_script.sh && \
    echo '    echo "Request $i failed"' >> /request_script.sh && \
    echo '  fi' >> /request_script.sh && \
    echo '  if [ $i -lt 10 ]; then' >> /request_script.sh && \
    echo '    sleep 5' >> /request_script.sh && \
    echo '  fi' >> /request_script.sh && \
    echo 'done' >> /request_script.sh && \
    echo 'echo "All requests completed"' >> /request_script.sh && \
    echo 'uname -a' >> /request_script.sh && \
    chmod +x /request_script.sh

CMD ["/request_script.sh"] 