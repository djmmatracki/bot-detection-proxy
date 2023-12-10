#!/bin/bash
docker rm bot-detector-proxy --force
docker rm social-media-api --force
docker rm social-media-app --force

# docker image rm registry.gitlab.com/onitsoft/internal/bot-detector-proxy:v0.3.3
# docker build -t registry.gitlab.com/onitsoft/internal/bot-detector-proxy:v0.3.3 .

docker run -p 0.0.0.0:8200:8000 --network bot-detector -d --name bot-detector-proxy --mount type=bind,source=/home/dmatrack/BotDetectionProxy/templates,target=/templates --mount type=bind,source=/home/dmatrack/BotDetectionProxy/config,target=/config registry.gitlab.com/onitsoft/internal/bot-detector-proxy:v0.3.3
docker run --network bot-detector -d --name social-media-api dominikmatracki/social-media-api:latest
docker run --network bot-detector -d --name social-media-app dominikmatracki/social-media-app:latest
