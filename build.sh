#!/bin/bash

# Build the Go application for the current OS and architecture
go build -o flowguard .

# Build the Go application for Linux AMD64
GOOS=linux GOARCH=amd64 go build -o flowguard-linux-amd64 .
