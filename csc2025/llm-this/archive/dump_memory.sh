#!/bin/bash

# Run program in background
./llm-this &
PID=$!

sleep 0.1

# Dump memory
if [ -d "/proc/$PID" ]; then
    cat /proc/$PID/maps
    echo "Dumping memory..."
    gcore -o coredump $PID 2>&1
fi

wait $PID
