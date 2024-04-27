#!/bin/bash
echo "Bash Implemetation of an ADB ScreenShotter. Auto Screenshots the connected ADB device every 5 seconds. DOES NOT save them"
echo -e "\\tNote, there may be delay due to image transfer time."
echo "ONLY USE WHEN YOU HAVE PERMISSION!"


duration=5 # Duration to keep the viewer open in seconds

while true; do
    adb shell screencap -p > screen.png
    # Open the image in the background
    open screen.png &
    viewer_pid=$!

    # Sleep for the specified duration
    sleep $duration
    # Kill the viewer
    kill $viewer_pid
    # Optional: wait before taking the next screenshot
    #sleep 1

done
