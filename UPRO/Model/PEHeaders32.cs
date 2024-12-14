using System.Runtime.InteropServices;

namespace UPRO.Model
{
    // IMAGE_DOS_HEADER (루트에 가까운 최상위 헤더)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;    // Magic number
        public ushort e_cblp;     // Bytes on last page of file
        public ushort e_cp;       // Pages in file
        public ushort e_crlc;     // Relocations
        public ushort e_cparhdr;  // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss;       // Initial (relative) SS value
        public ushort e_sp;       // Initial SP value
        public ushort e_csum;     // Checksum
        public ushort e_ip;       // Initial IP value
        public ushort e_cs;       // Initial (relative) CS value
        public ushort e_lfarlc;   // File address of relocation table
        public ushort e_ovno;     // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;   // Reserved words
        public ushort e_oemid;    // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;  // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;   // Reserved words
        public int e_lfanew;      // File address of new exe header (PE header offset)
    }

    // IMAGE_NT_HEADERS(IMAGE_FILE_HEADER와 IMAGE_OPTIONAL_HEADER를 포함하는 트리 구조)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_NT_HEADERS
    {
        public uint Signature;                  // "PE" 파일 시그니처
        public IMAGE_FILE_HEADER FileHeader;    // 상위의 파일 헤더 포함
        public IMAGE_OPTIONAL_HEADER OptionalHeader; // 상위의 옵션 헤더 포함
    }


    // IMAGE_FILE_HEADER
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    // IMAGE_OPTIONAL_HEADER (하위에 여러 데이터 디렉토리와 함께 NT 헤더에 속함)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic;                      // Identifies as 32-bit (0x10B for PE32)
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;                   // 32-bit specific
        public uint ImageBase;                    // 32-bit specific
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;           // 32-bit specific
        public uint SizeOfStackCommit;            // 32-bit specific
        public uint SizeOfHeapReserve;            // 32-bit specific
        public uint SizeOfHeapCommit;             // 32-bit specific
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory; // 데이터 디렉토리 배열을 포함
    }

    // IMAGE_DATA_DIRECTORY (데이터 디렉토리는 여러 종류의 데이터를 가리킴)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress; // RVA (Relative Virtual Address)
        public uint Size;           // 크기
    }

    // IMAGE_SECTION_HEADER (섹션 헤더는 NT 헤더의 하위로 여러 개 존재할 수 있음)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;            // Section name (8 bytes)
        public uint VirtualSize;       // Virtual size
        public uint VirtualAddress;    // Virtual address (RVA)
        public uint SizeOfRawData;     // Size of raw data (on disk)
        public uint PointerToRawData;  // Pointer to raw data (on disk)
        public uint PointerToRelocations; // Pointer to relocations
        public uint PointerToLinenumbers; // Pointer to line numbers
        public ushort NumberOfRelocations; // Number of relocations
        public ushort NumberOfLinenumbers; // Number of line numbers
        public uint Characteristics;   // Section characteristics
    }

    // IMAGE_IMPORT_DESCRIPTOR
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        public uint TimeDateStamp;      // 0 if not bound,
                                        // -1 if bound, and real date/time stamp
                                        // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                        // O.W. date/time stamp of DLL bound to (Old BIND)
        public uint ForwarderChain;     // -1 if no forwarders
        public uint Name;               // RVA to DLL name
        public uint FirstThunk;         // RVA to IAT (if bound this IAT has actual addresses)
    }

    // IMAGE_THUNK_DATA
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_THUNK_DATA
    {
        [FieldOffset(0)]
        public uint ForwarderString;  // INT에서 주소를 가리키거나 Forwarder 문자열

        [FieldOffset(0)]
        public uint Function;         // IAT에서 메모리 주소

        [FieldOffset(0)]
        public uint Ordinal;          // 함수의 Ordinal 값

        [FieldOffset(0)]
        public uint AddressOfData;    // INT에서 이름과 힌트를 가리키는 주소
    }

    // IMAGE_IMPORT_BY_NAME
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_IMPORT_BY_NAME
    {
        public ushort Hint;           // Hint index for faster lookups
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Name;           // ASCII string for the name of the function
    }

}
