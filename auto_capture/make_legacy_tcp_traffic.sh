#!/bin/bash

# Outer loop to run 1000 times
for iteration in $(seq 1 1000); do
    echo "Iteration $iteration of 1000"
    
    # Inner loop to create 20 connections
    for connection in $(seq 1 20); do
        # Generate message.txt with 32 bytes of random data
        head -c 32 /dev/urandom > message.txt

        # Start netcat in the background and get its PID
        nc 10.30.0.1 5555 < message.txt &
        nc_pid=$!

	sleep 3

	kill -9 $nc_pid
	wait > /dev/null 2>&1

        # Optional sleep to avoid overwhelming the system
        sleep 1
    done
done

