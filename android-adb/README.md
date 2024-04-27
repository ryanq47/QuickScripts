## About

This is a set of tools used to make ADB stuff easier, basically macro commands. They are meant to be quick and dirty. 

A few things are assumed before running these tools:
 - 1. You only have one device connected to ADB. Multiple are not supported. use `adb connect IP` to connect a device.
 - 2. This device does not have a password. 


#### Files
All useful files are stored in the 'data' directory. Each tool has its own folder. 

Ex: tmp/adb_pull_databases/<\data\>

Note, there is no way to distigusih between device data in here, aka if you pull the DB's on 2 different devices, the 2nd will overwrite the first. 