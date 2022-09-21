$someValue = "{"
$filePath = "C:\temp\SplunkRead\"

$tempLogFields = Import-Csv -Path .\logFields.csv
$tempLogRules = Import-Csv -Path .\logRule.csv

if ($IsWindows -eq $true){
    $directoryExists = Test-Path "C:\temp\SplunkRead"
    $filePath = "C:\temp\SplunkRead\"
    if($directoryExists -eq $true){
        #do nothing
    }
    else{
        New-Item -Path "C:\temp\SplunkRead" -ItemType Directory
        }    
}
elseif ($IsLinux -eq $true) {
    $directoryExists = Test-Path "/var/log/SplunkRead"
    $filePath = "/var/log/SplunkRead/"
    if($directoryExists -eq $true){
        #do nothing
    }
    else{
        New-Item -Path "/var/log/SplunkRead" -ItemType Directory
    }
}

function Determine-Value {
    param ( 
        [Parameter(Mandatory = $true)] [string] $fieldData,
        [Parameter(Mandatory = $true)] [string] $randomParameter
        )

        write-host "Determine Value " $fieldData + " and " $randomParameter
    if($fieldData.EndsWith(".csv") -and $randomParameter -eq "na"){
        write-host "Inside CSV"
        $tempCSVPath = ".\" + $fieldData
        $tempCSV = Import-Csv -Path $tempCSVPath
        $tempCount = $tempCSV.count
        $x = Get-Random -Minimum 1 -Maximum $tempCount
        $x -= 1
        #Write-Host "I win " + $tempCSV[$x].Name
        $bar = $tempCSV[$x].Name
       # write-host $bar
        return $bar
    }
    if($fieldData.EndsWith(".csv") -and $randomParameter -eq "complex"){
        Write-Host "Inside CSV and Complex"
        $tempCSVPath = ".\" + $fieldData
        $tempCSV = Import-Csv -Path $tempCSVPath
   
        $tempCount = $tempCSV.count
        $x = Get-Random -Minimum 1 -Maximum $tempCount
        $x -= 1
        #Write-Host "I win " + $tempCSV[$x].Name
        $bar = $tempCSV[$x].Name
       # write-host $bar
        return $bar
    }
    elseif($fieldData.EndsWith(".csv") -and $randomParameter -like '*,*'){
        $tempCSV = $randomParameter.Split(",")
        #Write-Host "TempCSV is " $tempCSV.count
        $someInt = $tempCSV[0]
        #Write-Host "TempCSV 0 index is " $someInt

        $tempCSVPath = ".\" + $fieldData
        $importCSV = Import-Csv -Path $tempCSVPath
        $tempCount = $importCSV.count - 1
        $x = Get-Random -Minimum 1 -Maximum $tempCount
        $x -= 1
        $y = 0
        $firstValue = $importCSV[$x].Name

        $myRandValues = Get-Random -Count 2 -InputObject (0..$tempCount)
         Write-Host  $myRandValues.count
      Write-Host $myRandValues[0]
      Write-Host $myRandValues[1]
      Write-Host $importCSV[$myRandValues[0]].Name
      Write-Host $importCSV[$myRandValues[1]].Name

        $tempString = $importCSV[$myRandValues[0]].Name + '","' + $tempCSV[2] + '":"' + $importCSV[$myRandValues[1]].Name
        write-host "Multifield value" $tempString

        return $tempString
    
    }
    elseif($fieldData -eq "range"){
        write-host "inside Range"
        write-host $randomParameter
        $tempArray = $randomParameter.Split("-")
        
        write-host "Split MV " $tempArray[0] " " $tempArray[1]

        $x = Get-Random -Minimum $tempArray[0] -Maximum $tempArray[1]
        write-host "x = " $x
        return $x
    }
    elseif($fieldData -eq "mv"){
        write-host $randomParameter
        $tempArray = $randomParameter.Split(",")
        $tempCount = $tempArray.count   
        
        $maxValue = $tempCount + 1 

        $x = Get-Random -Minimum 1 -Maximum $maxValue
        write-host "Split MV " $maxValue " " $x
       
        write-host "x = " $x
        return $tempArray[$x]
    }
    else{
        return $fieldData
    }


}

function Start-Menu {
    Do {
        write-host "*********************************************************************"
        write-host "***                Choose Your Startup Option                     ***"
        write-host "***                1) Start Server With Scenarios                 ***"
        write-host "***                2) Run EventGen                                ***"
        write-host "***                3) Run Scenario                                ***"
        write-host "*********************************************************************"
    
        $prompt2 = Read-Host "Which Option Would You Like to Run?"
    
        $startupOption = [int]$prompt2
    
        if ($startupOption -eq 1 -or $startupOption -eq 2 -or $startupOption -eq 3) {
            $strQuit = "n" 
        }
        else {
    
            $strQuit = Read-Host "`n    ERROR: The input is not an Integer between 1 and 3. `n
    
            Would you like to try another input? (Y/N)"
    
            }
    
    }
    While ($strQuit -ne "N")

    if ($startupOption -eq 1){
        [int]$runTime= Prompt-ForLoopTime
        write-host "The Time is + " $runTime
   
        Generate_RandomLog -runTime $runTime
       
    }
    elseif($startupOption -eq 2){
        $runTime = Prompt-ForLoopTime
        Generate_RandomLog -runTime $runTime
    }
    elseif($startupOption -eq 3){
 
    }
    else{
    create-softwareEvent
    }
}

function Prompt-ForLoopTime{
    [int]$SplunkGenTime = Read-Host "How long do you want to auto generate logs (in minutes) 2880 is two days?"
    
    write-host "The input was " = $SplunkGenTime
    return $SplunkGenTime

}

Function Generate_RandomLog{
    param([Parameter(Mandatory = $true)] [int] $runTime)
    $runTime
    $TimeEnd = (get-date).AddMinutes($runTime)
    $TimeNow = Get-Date
    
    write-host $TimeStart
    write-host $TimeEnd
    write-host $TimeNow

    Do
    {
        write-host "In Loop"
        $TimeNow = Get-Date 

        $rand_event = Get-Random -Minimum -1 -Maximum 100

        write-host $rand_event

        if($rand_event -gt 1 -and $rand_event -lt 25){
            write-host "Writing a log"
            Write-RandomLog -LogID $tempLogRules.key[0] -LogLocation $tempLogRules.logname[0]
        }
        elseif($rand_event -gt 24 -and $rand_event -lt 50){
            write-host "Writing a dns log"
            Write-RandomLog -LogID $tempLogRules.key[1] -LogLocation $tempLogRules.logname[1]
            #Create-ExternalWebEvent
        }
        elseif($rand_event -gt 49 -and $rand_event -lt 75){
            write-host "Writing a http log"
            Write-RandomLog -LogID $tempLogRules.key[2] -LogLocation $tempLogRules.logname[2]
            #create-vpnevent
        }
        elseif($rand_event -gt 49 -and $rand_event -lt 60){
            #Create-WebEvent
        }
        elseif($rand_event -gt 59 -and $rand_event -lt 70){
            #Create-SSHEvent
        }
        elseif($rand_event -gt 69 -and $rand_event -lt 80){
            #Create-RDPEvent
        }
        elseif($rand_event -gt 79 -and $rand_event -lt 90){
            #Create-SoftwareEvent
        }
        else{
            #create-microsoftSQLEvent
        }
        start-sleep -seconds .5
    }  
    Until ($TimeNow -ge $TimeEnd)
}

Function Write-RandomLog {
    param([Parameter(Mandatory = $true)] [string] $LogID,
    [Parameter(Mandatory = $true)] [string] $LogLocation)

    $timeManipulation = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    #$counter = 1
    $someValue = '{"ts":"' + $timeManipulation + '"'
    
    $tempLogFields | ForEach-Object {
       write-host "Evaluating log id " $_.logID
        if($_.logID -eq $LogID){
                write-host "Writing Log"    
                $foo =  Determine-Value -fieldData $_.fieldData -randomParameter $_.randomParameter
                write-host "Value " $foo
                $someValue += ',"' + $_.name + '":"' + $foo + '"' 
                     
        }
    } 
    
    $someValue += "}"
    
    $filePathTemp = $filePath + $LogLocation
    $someValue | Out-File $filePathTemp -Append -Encoding utf8BOM
}

Start-Menu





