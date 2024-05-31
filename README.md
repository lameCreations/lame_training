# Lame-Training-SplunkApp
 A splunk app that will teach the basics of how to hunt for data in Splunk Logs. The lame_training zip can just be added to splunk as a new app.  For a video demoing how to install the app, you can use the following youtube video.  
 
 https://www.youtube.com/watch?v=ryawiRdN9B0
 
If you are just using the app for the ability to search my videos or you are using it for a quick reference to Splunk tips and tricks you will not need to add anything else to this app, but if you are following along with some of my training tutorials, you have a few options to create sample data to work with.  My newer training tutorials focus on using the Botsv3 data set from Splunk.  This can be downloaded from Splunk's Github site.  The documentation for this app is contained on their git site.  

https://github.com/splunk/botsv3

Additionally, I have added an app that contains some sample network logs that I have used in most of my tutorials. This is far and away the easiest way to have the conn logs that I use in many of my training tutorials.  

I also offer three types of eventgen data.  Eventgen data is data that will create "psuedo random" logs on your system, that are current and can be used for my tutorials.  The Splunk Eventgen app is a cool conceptual idea that is easy to use, but not easy for peole designing the data and has lost a lot of steam over the years as most people building Splunk apps are opting to no longer include sample data that can be run in eventgen, but it is always an option for you to generate a set of data for training.  

1) eventgen that is cim compliant - this data comes with all of its fields CIM compliant.
https://github.com/lameCreations/lame_eventgen
   
2) eventgen data that is not CIM compliant, this can be useful to use when trying to learn how to accelerate data, use data models and making your data Splunk CIM compliant.
https://github.com/lameCreations/lame_eventgen_nonCIM

3) the last eventgen method I provide, is my own custom eventgen process. I have built one that works with powershell and one that works with Python code.  While the above two methods are really simple, they also provide little flexibility in scenario creation.  This app allows for scenarios to be written into csv files and then replayed so that training can involve looking for specific actions in the data.  I have used this to simulate attacks on my network and service degradation.  At this moment, there is not training on how to use this app, but I am in the process of generating it.  This app is for those who really want granularitiy in their eventgen.  Definitely NOT for beginners.
https://github.com/lameCreations/LAME_EventGenerator

The Lame Training Splunk app contains the inputs.conf files to read the log files that are created by the powershell EventGenerator scripts. If you don't add this app, your logs won't be read into splunk.  The props.conf file is also included to make sure the logs are parsed as json files.

The eventgenerator is not essential for the app to work, but it allows you to have nearly identical data as the tutorials in this app which should simplify the process of learning the overall concept.   
