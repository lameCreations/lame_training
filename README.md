# Lame-Training-SplunkApp
 A splunk app that will teach the basics of how to hunt for data in Splunk Logs. 
 
 The lame_training zip can just be added to splunk as a new app.  The app contains the inputs.conf files to read the log files that are created by the powershell EventGenerator scripts. If you don't add this app, your logs won't be read into splunk.  The props.conf file is also included to make sure the logs are parsed as json files.
 
The PowerShell eventgenerator to create the tutorial data is not included in this repo.  Please download the code from 
https://github.com/lameCreations/LAME_EventGenerator
to have the ability to create lame_training logs.  
 
The eventgenerator is not essential for the app to work, but it allows you to have nearly identical data as the tutorials in this app which should simplify the process of learning the overall concept.   

This app has a KV store for sourcetype details and potential analtyics.  Instead of entering this data in yourself, feel free to download the two csv files and import them into L.A.M.E. EDU associated KV Lookup.
