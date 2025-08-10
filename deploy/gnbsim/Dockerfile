# Copyright 2021-present Open Networking Foundation
# Copyright 2024-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.24.4-bookworm AS builder

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    vim \
    ethtool \
    git && \
    apt-get clean

WORKDIR $GOPATH/src/gnbsim

ARG VERSION

# Clone the repository instead of copying context files
RUN git clone https://github.com/omec-project/gnbsim.git . 
RUN git checkout v$VERSION
RUN make all

FROM alpine:3.22 AS gnbsim

LABEL maintainer="UnifyAir <support@unifyair.com>"

ARG DEBUG_TOOLS

RUN apk update && apk add --no-cache -U bash tcpdump

# Install debug tools ~ 50MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ]; then \
        apk update && apk add --no-cache -U gcompat vim strace net-tools curl netcat-openbsd bind-tools; \
        fi

WORKDIR /gnbsim

# Copy executable
COPY --from=builder /go/src/gnbsim/bin /usr/local/bin/.