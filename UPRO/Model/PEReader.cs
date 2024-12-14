using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using UPRO.Util;

namespace UPRO.Model
{
    public class PEReader
    {
        public byte[] Buffer;
        public IMAGE_DOS_HEADER DosHeader;
        public IMAGE_NT_HEADERS NtHeader;
        public int FileHeaderOffset;
        public int OptionalHeaderOffset;
        public int SectionHeaderOffset;
        public IMAGE_SECTION_HEADER[] SectionHeaders;

        private readonly int CodeStart;
        private readonly int CodeEnd;

        // 생성자
        public PEReader(string filePath) 
        {
            Buffer = File.ReadAllBytes(filePath);
            
            DosHeader = ReadStructureFromBuffer<IMAGE_DOS_HEADER>(0);
            var NtHeaderOffset = DosHeader.e_lfanew;
            FileHeaderOffset = NtHeaderOffset + 4;

            OptionalHeaderOffset = DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + 4;// Signature 사이즈 4 추가

            NtHeader = ReadStructureFromBuffer<IMAGE_NT_HEADERS>(DosHeader.e_lfanew);

            SectionHeaderOffset = DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS));// 섹션헤더 offset

            SectionHeaders = ReadSectionHeaders(NtHeader.FileHeader.NumberOfSections, SectionHeaderOffset); //섹션헤더 배열 읽기(섹션 갯수, 섹션헤더 시작 offset)

            CodeStart = GetCodeSectionRange().Start;
            CodeEnd = GetCodeSectionRange().End;
        }

        // 코드섹션(첫번째 섹션) 시작 끝 offset 가져오기
        private (int Start, int End) GetCodeSectionRange()
        {
            int start = (int)SectionHeaders[0].PointerToRawData;
            int end = start + (int)SectionHeaders[0].SizeOfRawData;
            return (start, end);
        }

        // 섹션헤드 배열 읽기
        private IMAGE_SECTION_HEADER[] ReadSectionHeaders(int sectionNumber, int sectionHeaderOffset)
        {
            var sectionHeaders = new IMAGE_SECTION_HEADER[sectionNumber];

            for (int i = 0; i < sectionNumber; i++)
            {
                // 각 섹션 헤더는 IMAGE_SECTION_HEADER 크기만큼 떨어져 있음
                int offset = sectionHeaderOffset + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));

                // 섹션 헤더 읽기
                sectionHeaders[i] = ReadStructureFromBuffer<IMAGE_SECTION_HEADER>(offset);
            }
            return sectionHeaders;
        }

        // 특정 오프셋에서 구조체를 파싱하는 메서드
        private T ReadStructureFromBuffer<T>(int offset) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufferPtr = handle.AddrOfPinnedObject();
                IntPtr structPtr = IntPtr.Add(bufferPtr, offset);
                return Marshal.PtrToStructure<T>(structPtr);
            }
            finally
            {
                handle.Free();
            }
        }

        // Rva -> Offset(Raw) 변환
        public int RvaToRaw(int rva)
        {
            uint urva = (uint)rva;
            foreach (var section in SectionHeaders)
            {
                // 섹션의 메모리 시작 주소와 크기를 확인
                if (urva >= section.VirtualAddress && urva < section.VirtualAddress + section.VirtualSize)
                {
                    // RVA는 섹션 내에서의 오프셋을 포함하므로, 섹션 시작 오프셋을 더해줍니다
                    return (int)(urva - section.VirtualAddress + section.PointerToRawData);
                }
            }

            throw new Exception("RVA is outside of the valid section");
        }

        // Raw(offset) -> VA 변환
        public int RawToVa(int raw)
        {
            uint uraw = (uint)raw;
            foreach (var section in SectionHeaders)
            {
                if (uraw >= section.PointerToRawData && uraw < section.PointerToRawData + section.SizeOfRawData)
                {
                    return (int)(NtHeader.OptionalHeader.ImageBase + section.VirtualAddress + (uraw - section.PointerToRawData));
                }
            }
            throw new ArgumentException("Raw address not within any section");
        }

        // VA -> Raw(offset) 변환
        public int VaToRaw(int va)
        {
            foreach (var section in SectionHeaders)
            {
                uint uva = (uint)va;
                // VA가 섹션의 VA 범위에 있는지 확인
                if (uva >= NtHeader.OptionalHeader.ImageBase + section.VirtualAddress &&
                    uva < NtHeader.OptionalHeader.ImageBase + section.VirtualAddress + section.VirtualSize)
                {
                    // Raw 주소로 변환
                    return (int)(section.PointerToRawData + (uva - (NtHeader.OptionalHeader.ImageBase + section.VirtualAddress)));
                }
            }
            throw new ArgumentException("Virtual address not within any section");
        }

        // offset 주소에서 Dword 값 반환
        public int FetchDWord(int offset)
        {
            if (offset < 0 || offset > Buffer.Length - 4)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset is outside the bounds of the data array");
            }

            return BitConverter.ToInt32(Buffer, offset);
        }

        // 문자열 검색결과 Va값 반환
        public int StringVa(string str)
        {
            int offset = FindStringOffset(str); //문자열 검색
            if (offset == -1)
            {
                return -1; // 문자열을 찾지 못한 경우
            }
            return RawToVa(offset); // raw offset을 VA로 변환해서 반환
        }

        // 문자열 검색결과 Offset값 반환
        public int StringOffset(string str)
        {
            return FindStringOffset(str);
        }

        // 문자열 검색 
        private int FindStringOffset(string str)
        {
            // 문자열을 바이트 배열로 변환
            byte[] searchString = Encoding.ASCII.GetBytes(str);
            byte[] pattern = new byte[searchString.Length + 2];
            pattern[0] = 0x00; // 시작 부분 null byte
            Array.Copy(searchString, 0, pattern, 1, searchString.Length);
            pattern[pattern.Length - 1] = 0x00; // 끝 부분 null byte

            // 검색할 바이트 배열의 길이
            int searchLength = pattern.Length;

            for (int i = 0; i <= Buffer.Length - searchLength; i++)
            {
                bool found = true;
                for (int j = 0; j < searchLength; j++)
                {
                    if (Buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i + 1; // 문자열 시작 오프셋 반환
                }
            }
            // 문자열을 찾지 못한 경우 -1 반환
            return -1;
        }

        // 문자열 패턴을 byte[]와 와일드카드 정보를 포함한 배열로 변환하는 함수
        private (byte[] pattern, byte?[] wildCards) ParsePatternString(string patternString)
        {
            // 공백으로 패턴을 분리
            string[] tokens = patternString.Split(' ');

            byte[] pattern = new byte[tokens.Length];
            byte?[] wildCards = new byte?[tokens.Length];

            for (int i = 0; i < tokens.Length; i++)
            {
                if (tokens[i] == "??")
                {
                    pattern[i] = 0; // 기본 값으로 설정
                    wildCards[i] = null; // 와일드카드로 처리
                }
                else
                {
                    // 16진수 문자열을 byte로 변환
                    pattern[i] = Convert.ToByte(tokens[i], 16);
                    wildCards[i] = pattern[i]; // 해당 바이트 값으로 설정
                }
            }

            return (pattern, wildCards);
        }

        // 실행코드 영역에서 패턴검색 첫번째 결과 반환
        public int FindCode(string patternString, int start = -1, int end = -1)
        {
            // 문자열 패턴을 byte[]로 변환
            (byte[] pattern, byte?[] wildCards) = ParsePatternString(patternString);

            int patternLength = pattern.Length;

            // start와 end의 기본값 설정
            if (start == -1) start = CodeStart;
            if (end == -1) end = CodeEnd;

            // 검색 범위를 한정
            for (int i = start; i <= end - patternLength; i++)
            {
                bool isMatch = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (!wildCards[j].HasValue)
                    {
                        // 와일드카드 값인 경우, 어떤 값이 와도 상관없음
                        continue;
                    }
                    if (Buffer[i + j] != pattern[j])
                    {
                        isMatch = false;
                        break;
                    }
                }
                if (isMatch)
                {
                    return i; // 첫 번째 일치하는 오프셋 반환
                }
            }

            return -1; // 일치하는 값을 찾지 못한 경우 -1 반환
        }

        // 실행코드 영역에서 패턴검색 및 검색결과 전부반환
        public List<int> FindCodes(string patternString, int start = -1, int end = -1)
        {
            // 문자열 패턴을 byte[]로 변환
            (byte[] pattern, byte?[] wildCards) = ParsePatternString(patternString);

            List<int> matches = new List<int>();
            int patternLength = pattern.Length;

            // start와 end의 기본값 설정
            if (start == -1) start = CodeStart;
            if (end == -1) end = CodeEnd;

            // 검색범위 한정
            for (int i = start; i <= end - patternLength; i++)
            {
                bool isMatch = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (!wildCards[j].HasValue)
                    {
                        // 와일드카드 값인 경우, 어떤 값이 와도 상관없음
                        continue;
                    }
                    if (Buffer[i + j] != pattern[j])
                    {
                        isMatch = false;
                        break;
                    }
                }
                if (isMatch)
                {
                    matches.Add(i);
                }
            }
            return matches;
        }

        // offset위치 byte값 변경
        public void ReplaceByte(int offset, byte value)
        {
            if (offset < 0 || offset >= Buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset is outside the bounds of the array.");
            }
            Buffer[offset] = value;
        }

        // 문자열을 byte 배열로 변환
        private byte[] ParseHexString(string hexString)
        {
            // 공백을 기준으로 문자열을 분리하고, 각 항목을 16진수 바이트로 변환
            string[] hexValues = hexString.Split(' ');
            byte[] byteArray = new byte[hexValues.Length];

            for (int i = 0; i < hexValues.Length; i++)
            {
                byteArray[i] = Convert.ToByte(hexValues[i], 16); // 16진수 문자열을 byte로 변환
            }

            return byteArray;
        }

        // offset 위치부터 Hex string으로 변경
        public void ReplaceHex(int offset, string hexString)
        {
            // 문자열을 16진수 바이트 배열로 변환
            byte[] value = ParseHexString(hexString);

            // 기존 바이트 배열을 처리하는 메소드 호출
            ReplaceHex(offset, value);
        }

        // offset 위치부터 바이트 배열 값 변경
        public void ReplaceHex(int offset, byte[] value)
        {
            if (offset < 0 || offset >= Buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset is outside the bounds of the array.");
            }

            if (offset + value.Length > Buffer.Length)
            {
                throw new ArgumentException("Value array is too large to fit at the given offset.");
            }
            Array.Copy(value, 0, Buffer, offset, value.Length);
        }

        // PE 파일 저장
        public void SaveFile(string filePath)
        {
            File.WriteAllBytes(filePath, Buffer);
        }

        // DLL 함수 주소 찾기
        public int FindFunctionAddress(string NameOfDll, string NameOfFunction)
        {
            // Import Directory의 시작 위치 (RVA)
            uint importDirectoryRVA = NtHeader.OptionalHeader.DataDirectory[1].VirtualAddress;

            // Import Directory가 없는 경우
            if (importDirectoryRVA == 0)
                return (int)IntPtr.Zero;

            // Import Directory의 실제 파일 오프셋 계산
            int importDirectoryOffset = RvaToRaw((int)importDirectoryRVA);

            // Import Descriptor를 읽음
            while (true)
            {
                // IMAGE_IMPORT_DESCRIPTOR 구조체 읽기
                IMAGE_IMPORT_DESCRIPTOR importDescriptor = ReadStructureFromBuffer<IMAGE_IMPORT_DESCRIPTOR>(importDirectoryOffset);

                // 종료 조건
                if (importDescriptor.Name == 0)
                    break;

                // DLL 이름을 읽음
                string dllName = ReadNullTerminatedString(RvaToRaw((int)importDescriptor.Name));

                // 해당 dll을 찾음
                if (dllName.Equals(NameOfDll, StringComparison.OrdinalIgnoreCase))
                {
                    // Import Lookup Table (ILT)와 IAT 확인
                    int iltOffset = RvaToRaw((int)importDescriptor.OriginalFirstThunk);
                    int iatOffset = RvaToRaw((int)importDescriptor.FirstThunk);

                    // IAT 또는 ILT에서 함수 찾기
                    while (true)
                    {
                        // Hint/Name Table을 읽음
                        IMAGE_THUNK_DATA thunkData = ReadStructureFromBuffer<IMAGE_THUNK_DATA>(iltOffset);

                        // 종료 조건
                        if (thunkData.AddressOfData == 0)
                            break;

                        // 함수 이름 확인
                        string functionName = ReadNullTerminatedString(RvaToRaw((int)thunkData.AddressOfData + 2));

                        // 해당 함수 찾음
                        if (functionName.Equals(NameOfFunction, StringComparison.OrdinalIgnoreCase))
                        {
                            // IAT에서 해당 함수의 주소를 반환
                            return (int)(new IntPtr(iatOffset));
                        }

                        // 다음 엔트리로 이동
                        iltOffset += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA));
                        iatOffset += Marshal.SizeOf(typeof(IMAGE_THUNK_DATA));
                    }
                }

                // 다음 Import Descriptor로 이동
                importDirectoryOffset += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
            }

            return (int)IntPtr.Zero;
        }

        // null-terminated 문자열을 읽기 위한 메서드
        private string ReadNullTerminatedString(int startOffset)
        {
            List<byte> byteList = new List<byte>();
            int index = startOffset;  // 시작 오프셋 설정

            // fileBytes 배열의 IAT에서  null 종료 문자(\0)를 만날 때까지 읽기
            while (index < Buffer.Length && Buffer[index] != 0)
            {
                byteList.Add(Buffer[index]);
                index++;
            }

            return Encoding.UTF8.GetString(byteList.ToArray());
        }

        // 섹션 정렬 체크(VA, RAW Address)
        public int Align(int value, int alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        // 섹션 이름 변경
        public byte[] GetSectionNameBytes(string sectionName)
        {
            // 섹션 이름은 최대 8바이트이므로, 그 이상일 경우 잘라냅니다.
            byte[] nameBytes = new byte[8];

            // 문자열을 바이트 배열로 변환 (ASCII로 인코딩)
            byte[] stringBytes = System.Text.Encoding.ASCII.GetBytes(sectionName);

            // 섹션 이름이 8바이트보다 길면 잘라내고, 짧으면 나머지는 0x00으로 채움
            Array.Copy(stringBytes, nameBytes, Math.Min(stringBytes.Length, 8));

            return nameBytes;
        }

        // 구조체를 바이트 배열로 변환하는 함수
        public byte[] StructToBytes<T>(T structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] bytes = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, true);
            Marshal.Copy(ptr, bytes, 0, size);
            Marshal.FreeHGlobal(ptr);
            return bytes;
        }

        /// <summary>
        /// call offset 계산(리틀엔디언 문자열로 반환) 
        /// </summary>
        /// <param name="call">call 호출대상의 Raw 주소</param>
        /// <param name="offset">call 명령어 Raw 위치 주소</param>
        /// <returns>offset 반환</returns>
        public string CallOffset(int call, int offset)
        {
            return (RawToVa(call) - RawToVa(offset + 5)).PackToHex(4);
        }

        public int SrvType()
        {
            var str = "68 " + StringVa("servertype").PackToHex(4);
            var offset = FindCode(str);
            var addr = FindCode("C7 05 ?? ?? ?? ?? 01 00 00 00", offset + 5);
            return FetchDWord(addr + 2);
        }

        public int LangType()
        {
            var str = "68 " + StringVa("servicetype").PackToHex(4);
            var offset = FindCode(str);
            var addr = FindCode("C7 05 ?? ?? ?? ?? 01 00 00 00", offset + 5);
            return FetchDWord(addr + 2);
        }

        public string HWnd()
        {
            int CreateWindowExARaw = FindFunctionAddress("user32.dll", "CreateWindowExA");
            int CreateWindowExAVa = RawToVa(CreateWindowExARaw);
            string CreateWindowExA = CreateWindowExAVa.PackToHex(4);

            var code = "FF 15 " + CreateWindowExA + " " + // call dword ptr ds:[CreateWindowExA]
                       "A3 ?? ?? ?? ??";                  // mov dword ptr ds:[hWnd], eax
            var offset = FindCode(code);
            return FetchDWord(offset + 7).PackToHex(4);
        }
    }
}
