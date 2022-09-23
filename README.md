# Lame-Training-SplunkApp
 A splunk app and Eventgen script that will teach the basics of how to hunt for data in Splunk Logs. 
 
 The lame_training zip can just be added to splunk as a new app.  The app contains the inputs.conf files to read the log files that are created by the powershell scripts. If you don't add this app, your logs won't be read into splunk.  The props.conf file is also included to make sure the logs are parsed as json files
 
 The LogGenerator-PS folder contains a PowerShell script called LogGenerator_v2.ps1 file.  Just execute the ps1 file and you will be prompted for how long you want to run the eventgen.  As soon as the logs are created, and the above splunk app is installed, logs will be present within Splunk.  
