#!/bin/sh

# turn on upgrade LED
echo out > /sys/class/gpio/gpio37/direction
echo 0 > /sys/class/gpio/gpio37/value

# kill all process
killall startup.sh
killall python
