using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using UPRO.Model;
using UPRO.Util;


namespace UPRO.View
{
    /// <summary>
    /// UPRO.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class UPRO : Window
    {
        public ObservableCollection<Item> Items;
        private ObservableCollection<Item> filteredItems;
        public PEReader pe;
        public string FilePath;
        public int PatchCount;

        /// <summary>
        /// 생성자
        /// </summary>
        public UPRO()
        {
            InitializeComponent();
            this.Loaded += URPO_Loaded; // Load 이벤트 연결
            BtnApply.IsEnabled = false;
            BtnRecommended.IsEnabled = false;
            BtnLoadProfile.IsEnabled = false;
            BtnSaveProfile.IsEnabled = false;
        }

        #region Patch Method
        private bool FixChatAtBugFix(int id, string name)
        {
            var code = "74 04 " +       // je short
                       "C6 ?? ?? 00 " + // mov byte ptr ds:[eis+25],0 -> 1
                       "5F " +
                       "5E";
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "'@' check not found");
                return false;
            }

            //pe.ReplaceByte(offset + 5, 0x1);
            List<Patch> Patchs = new List<Patch>();            
            Patch patch = new Patch
            {
                Offset = offset + 5,
                Hex = "01"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool Disable1rag1Params(int id, string name)
        {
            var offset = pe.StringVa("1rag1");

            if (offset == -1)
            {
                MessageBox.Show("Error : " + name, "Failed in Step 1 - String not found");
                return false;
            }

            var strHex = offset.PackToHex(4);

            var code = "68 " + strHex + " " + // push addr
                       "57 " +                // push edi
                       "E8 ?? ?? ?? ?? " +    // call <JMP.&start>
                       "83 C4 08 " +          // add esp,8
                       "85 C0 " +             // test eax,eax
                       "75 ??";               // jne short addr2

            var jmpOffset = 16;
            offset = pe.FindCode(code);

            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed in Step 2 - Pattern not found");
                return false;
            }

            //pe.ReplaceByte(offset + jmpOffset, 0xEB); //75 -> EB
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + jmpOffset,
                Hex = "EB"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool DisableFilenameCHeck(int id, string name)
        {
            var hWnd = pe.HWnd();

            //Step 1 - Find the Comparison pattern
            var code = "84 C0 " +              // test al,al
                       "75 ?? " +              // jne short addr1
                       "6A 00 " +              // push 0
                       "6A 00 " +              // push 0
                       "68 ?? ?? ?? ?? " +     // push "정상적인 라그나로크..."
                       "FF 35 " + hWnd + " " + // push dword ptr ds:[hWnd]
                       "FF 15 ?? ?? ?? ??";    // call [MessageBox]

            int patchOffset = 2;
            var offset = pe.FindCode(code);

            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed in Step 1");
                return false;
            }
            //pe.ReplaceByte(offset + patchOffset, 0xEB); //75 -> EB
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + patchOffset,
                Hex = "EB"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool ReadDataFolderFirst(int id, string name)
        {
            var offset = pe.StringVa("loading");
            if (offset == -1)
            {
                MessageBox.Show("Error : " + name, "Failed in Step 1 - loading not found");
                return false;
            }

            var code = "68 " + offset.PackToHex(4) + " " + // push addr
                       "0F 45 CE " +                       // cmovne ecx,esi
                       "88 0D ?? ?? ?? ??";                // mov byte ptr ds:[addr2], r8
            var offset2 = pe.FindCode(code);

            if (offset2 == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed in Step 2 - loading reference missing");
                return false;
            }

            code = "90 8B";

            //pe.ReplaceHex(offset2 + 5, code);// 0F 45 -> 90 8B
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset2 + 5,
                Hex = code
            };
            Patchs.Add(patch);
            
            var ReadFolderFirst = pe.FetchDWord(offset2 + 10).PackToHex(4);

            code = "80 3D " + ReadFolderFirst + " 00 " + // cmp byte ptr ds:[addr1], 0
                   "74 ?? " +                           // je short addr2
                   "6A 00 " +                           // push 0
                   "68 80 00 00 00";                    // push 80h

            offset = pe.FindCode(code);

            Patchs = new List<Patch>();
            if (offset == -1)
            {
                code = "80 3D " + ReadFolderFirst + " 00 " + // cmp byte ptr ds:[addr1], 0
                        "0F 84 ?? ?? ?? ?? " +                // jump addr2
                        "6A 00 " +                            // push 0
                        "68 80 00 00 00";                     // push 80h
                offset = pe.FindCode(code);

                if (offset == -1)
                {
                    ShowErrorWindow("Error : " + name, "Failed in Step 3 - conditional jump after each comparison");
                    return false;
                }
                code = "90 90 90 90 90 90";
                //pe.ReplaceHex(offset + 7, "90 90 90 90 90 90"); //0F 84 ?? ?? ?? ?? -> 90 90 90 90 90 90
                patch = new Patch
                {
                    Offset = offset + 7,
                    Hex = code
                };
                Patchs.Add(patch);
            }
            else
            {
                code = "90 90";
                //pe.ReplaceHex(offset + 7, "90 90");// 74 ?? -> 90 90
                patch = new Patch
                {
                    Offset = offset + 7,
                    Hex = code
                };
                Patchs.Add(patch);
            }
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool RestoreOldLoginPacket(int id, string name)
        {
            var LANGTYPE = pe.LangType().PackToHex(4);
            var code = "E8 ?? ?? ?? ?? " +         //call addr1
                       "8B 0D " + LANGTYPE + " " + //mov ecx, ptr ds:[LangType]
                       "85 C9 " +                  //test ecx,ecx
                       "0F 84 ?? ?? 00 00 " +      //je addr3
                       "83 F9 12 " +               //cmp ecx,12
                       "0F 84 ?? ?? ?? ?? " +      //je addr4
                       "83 F9 0C " +               //cmp ecx,c
                       "0F 84 ?? ?? ?? ??";        //je addr5

            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed Restore Old Login Packet.");
                return false;
            }
            code = string.Join(" ", Enumerable.Repeat("90", 26));
            //pe.ReplaceHex(offset + 11, code);//  90 90 ......

            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 11,
                Hex = code
            };
            
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool RemoveOTPLogin(int id, string name)
        {
            var code = "6A 26 " +       //push 26h   -> push 0
                       "68 35 27 00 00";//push 2735h -> push 2710

            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed RemoveOTPLogin.");
                return false;
            }
            code = "6A 00 68 10";
            //pe.ReplaceHex(offset, code);
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool ChatFloodRemoveLimit(int id, string name)
        {
            var code = "83 7D 08 02 " + // cmp dword ptr ss:[epb+8],2
                       "7C ?? " +       // jl short address
                       "6A 00 " +       // push 0
                       "6A 00";         // push 0
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Error : " + name, "Failed ChatFloodRemoveLimit.");
                return false;
            }
            //pe.ReplaceByte(offset + 4, 0xEB);

            List<Patch> Patchs = new List<Patch>();
            Patch patch;
            if (id == 3)
            {
                code = OneTextBoxWindow("Number Input","Enter chat limit(0 - 127, deault : 2)","2");

                if(code == null || Int32.Parse(code) >= 127 || Int32.Parse(code) <= -1)
                {
                    ShowErrorWindow("Patch Error", "Patch Canceled.");
                    return false;
                }

                patch = new Patch
                {
                    Offset = offset + 3,
                    Hex = Int32.Parse(code).ToString("x")
                };
                Patchs.Add(patch);
            }
            else // Remove Limit
            {
                patch = new Patch
                {
                    Offset = offset + 4,
                    Hex = "EB"
                };
                Patchs.Add(patch);
            }
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool DisableSwearFilter(int id, string name)
        {
            var code = "6D 61 6E 6E 65 72 2E 74 78 74";
            var offset = pe.FindCode(code, 0, pe.Buffer.Length);
            if (offset == -1)
            {
                ShowErrorWindow("Failed DisableSwearFilter", "Error : " + name);
                return false;
            }
            //pe.ReplaceByte(offset, 0x00);
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset,
                Hex = "00"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool FixNpcDialogScroll(int id, string name)
        {
            var code = "83 7A 2C 10 75";
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed FixNpcDialogScroll.", "Error : " + name);
                return false;
            }
            //pe.ReplaceByte(offset + 4, 0xEB); // 75 -> EB
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 4,
                Hex = "EB"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool AddCloseButton(int id, string name)
        {
            var code = "B9 00 00 C2 02";
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed AddCloseButton.", "Error : " + name);
                return false;
            }
            //pe.ReplaceHex(offset + 3, "CB 02"); // C2 02 -> CB 02 // WS_CLIPCHILDREN WS_CAPTION WS_SYSMENU WS_MINIMIZEBOX WS_MAXIMIZEBOX
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 3,
                Hex = "CB 02"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool IncreaseMapQuality(int id, string name)
        {
            var code = "6A 01 " +
                "8D 85 ?? ?? ?? ?? " +
                "B9 ?? ?? ?? ?? " +
                "50 " +
                "68 00 01 00 00 " +
                "68 00 01 00 00 " +
                "E8";
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("CreateTexture CALL not found.", "Error : " + name);
                return false;
            }

            //pe.ReplaceByte(offset + 1, 0x4); // push 1 -> push 4
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 1,
                Hex = "04"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool RestoreClientinfoxmlNoHardCodedAddress(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData;// + 0x100;
            int startVa = pe.RawToVa(start);

            //No Address Port 함수 호출
            var code = "83 C4 1C " +
                       "E8 ?? ?? ?? ?? " +
                       "8D 8D ?? ?? ?? ?? " +
                       "51 " +
                       "8B C8 " +
                       "E8 ?? ?? ?? ??"; // call -> No Address 호출 주소로 변경
            var loc = 17;
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name);
                return false;
            }
            string noAddressPort = pe.CallOffset(start + 0x346, offset + loc);
            //pe.ReplaceHex(offset + loc + 1, noAddressPort);
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + loc + 1,
                Hex = noAddressPort
            };
            Patchs.Add(patch);

            //Clientinfo.xml 로드 함수 호출
            code = "E8 ?? ?? ?? ?? " +     // call -> Clientinfo.xml로 변경
                   "A1 ?? ?? ?? ?? " +     // mov eax,dword ptr ds:[]
                   "8B 3D ?? ?? ?? ?? " +  // mov edi,dword ptr ds:[]
                   "8B 35 ?? ?? ?? ?? " +  // mov esi,dword ptr ds:[]
                   "6A 00 " +              // push 0
                   "68";                   // push dword
            offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            string clientinfoxml = pe.CallOffset(start + 0x11, offset);
            //pe.ReplaceHex(offset + 1, clientinfoxml);
            patch = new Patch
            {
                Offset = offset + 1,
                Hex = clientinfoxml
            };
            Patchs.Add(patch);

            //Address Port 찾기
            code = pe.StringVa("127.0.0.1").PackToHex(4) + " 26 1B"; // 6950.PackToHex(2) = "26 1B"
            offset = pe.FindCode(code, 0, pe.Buffer.Length);
            if (offset == -1)
            {
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name);
                return false;
            }
            int optAddr = pe.RawToVa(offset);
            int otpPort = optAddr + 4;
            int clientInfoAddr = otpPort + 4;        // Server Addr (VA)
            int clientInfoPort = clientInfoAddr + 4; // Port   (VA)

            //gAuthHost , snprintf 찾기
            var host = pe.StringVa("kro-agency.ragnarok.co.kr").PackToHex(4);
            code = "52 " +              // push edx
                   "68 " + host + " " + // push kro-agency.ragnarok.co.kr
                   "68 ?? ?? ?? ?? " +  // push %s:%d
                   "6A FF " +           // push FFFFFFFF
                   "68 81 00 00 00 " +  // push 81
                   "68 ?? ?? ?? ?? " +  // push g_auth_host
                   "E8 ?? ?? ?? ?? " +  // call <snprintf>
                   "83 C4 18";          // add esp,18

            offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name);
                return false;
            }
            string g_auth_host = pe.FetchDWord(offset + 19).PackToHex(4); // g_auth_host 
            int snprintf = pe.RawToVa(offset + 23) + 5 + pe.FetchDWord(offset + 24); //  call 실제 주소(VA)

            string ss = pe.RawToVa(start + 0x33F).PackToHex(4); // %s:%s

            string www = pe.StringVa("http://www.ragnarok.co.kr").PackToHex(4);

            // No Address Port 
            // 수정위치 찾기
            var serverType = pe.SrvType().PackToHex(4);
            var port = pe.StringVa("6900").PackToHex(4);
            code = "8B 15 " + serverType + " " +       // mov edx,dword ptr ds:[g_serverType]
                   "A1 ?? ?? ?? ?? " +                 // mov eax,dword ptr ds:[addr2]
                   "8B 0D ?? ?? ?? ?? " +              // mov ecx,dword ptr ds:[addr3]
                   "C7 05 ?? ?? ?? ?? " + port + " " + // mov dword ptr ds:[addr3], "6900"
                   "C7 05 ?? ?? ?? ?? " + www + " " +  // mov dword ptr ds:[addr4], "http://www.ragnarok.co.kr"
                   "C6 05 ?? ?? ?? ?? 01";             // mov byte ptr ds:[addr5],1

            var targetOffset = pe.FindCode(code);
            if (targetOffset == -1)
            {
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name);
                return false;
            }
            var targetVa = pe.RawToVa(pe.FindCode(code));// 수정위치 VA 주소

            string snprintfAddress = pe.CallOffset(snprintf, targetVa + 29);

            code = "83 FA 03 " +            // cmp edx,3
                   "0F 87 ?? ?? ?? ?? " +   // ja addr
                   "FF 24 95 ?? ?? ?? ??"; // jmp dword ptr ds:[edx*4+addr2]

            offset = pe.FindCode(code, targetOffset + 0x30, targetOffset + 0x60);
            if (offset == -1)
            {
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name);
                return false;
            }

            int jaAddr = pe.RawToVa(offset + 3) + 6 + pe.FetchDWord(offset + 5); // ja 절대주소
            string jmpAddr = (jaAddr - (targetVa + 37 + 5)).PackToHex(4);

            //수정 할 코드
            code = "FF 35 " + clientInfoPort.PackToHex(4) + " " + // push dword ptr ds:[clientInfoPort];
                   "FF 35 " + clientInfoAddr.PackToHex(4) + " " + // push dword ptr ds:[clientInfoAddr];
                   "68 " + ss + " " +              // push %s:%s
                   "6A FF " +                      // push FFFFFFFF
                   "68 81 00 00 00 " +             // push 81
                   "68 " + g_auth_host + " " +     // push g_auth_host
                   "E8 " + snprintfAddress + " " + // call <snprintf>
                   "83 C4 18 " +                   // add esp,18
                   "E9 " + jmpAddr;                // jmp jmpaddr

            //pe.ReplaceHex(targetOffset, code);
            patch = new Patch
            {
                Offset = targetOffset,
                Hex = code
            };
            Patchs.Add(patch);

            code = "75 ?? " +                  // jne --> jmp
                   "FF 15 ?? ?? ?? ?? " +      // call dword ptr ds:[rand]
                   "99 " +                     // cdq
                   "B9 ?? ?? ?? ?? " +         // mov ecx, value
                   "F7 F9 " +                  // idiv dex
                   "8D 85 ?? ?? ?? ?? " +      // lea eax, dword ptr ss:[]
                   "81 C2";                    // add edx, value
            offset = pe.FindCode(code);
            if (offset == -1) 
            { 
                ShowErrorWindow("Failed NoHardCodedAddress.", "Error : " + name); 
                return false;
            }
            //pe.ReplaceByte(offset, 0xEB);
            patch = new Patch
            {
                Offset = offset,
                Hex = "EB"
            };
            Patchs.Add(patch);

            //pe.ReplaceHex(offset + 0x3A, g_auth_host);
            patch = new Patch
            {
                Offset = offset + 0x3A,
                Hex = g_auth_host
            };
            Patchs.Add(patch);

            //Restore Clientinfoxml 
            var obp1cd = pe.RawToVa(start + 0x1cd).PackToHex(4);
            var obp1c9 = pe.RawToVa(start + 0x1c9).PackToHex(4);
            var obp1d1 = pe.RawToVa(start + 0x1d1).PackToHex(4);
            var obp235 = pe.RawToVa(start + 0x235).PackToHex(4);
            var obp4cc = pe.RawToVa(start + 0x4cc).PackToHex(4);
            var obp4c8 = pe.RawToVa(start + 0x4c8).PackToHex(4);
            var obp4d0 = pe.RawToVa(start + 0x4d0).PackToHex(4);
            var obp534 = pe.RawToVa(start + 0x534).PackToHex(4);

            code = "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 4D F0 C7 01 ?? ?? ?? ?? C7 41 04 FF FF FF FF";
            var offset042 = pe.RawToVa(pe.FindCode(code));// call042 주소
            if (offset042 == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }

            var edx037 = (offset042 ^ 0x4955C327).PackToHex(4);

            code = "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 2C A1 ?? ?? ?? ?? 33 C5 89 45 F0 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B F9 8A 45 14 8B 55 08 88 45 D0 8B 45 0C 89 55 D4 85 C0";
            var offset0af = pe.RawToVa(pe.FindCode(code));// call0af 주소

            if (offset0af == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var edi055 = (offset0af ^ 0x4955C327).PackToHex(4);

            var push235 = (startVa + 0x235).PackToHex(4);

            code = "55 8B EC 53 8B D9 57 83 7B 28 00 74 ?? E8 ?? ?? ?? ?? 8B 43 2C 85 C0 74";
            var offset0f8 = pe.RawToVa(pe.FindCode(code));
            if (offset0f8 == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var edx0c9 = (offset0f8 ^ 0x4955C327).PackToHex(4);

            code = "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 51 56 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 8B F1 89 75 F0 C7 06 ?? ?? ?? ?? C7 45 FC 00 00 00 00 8B 46 04 83 F8 FF";
            var offset10a = pe.RawToVa(pe.FindCode(code));
            if (offset10a == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var eax0fd = (offset10a ^ 0x4955C327).PackToHex(4);

            code = "55 8B EC 56 8B 71 28 85 F6 75 07 33 C0 5E 5D C2 04 00";
            var offset187 = pe.RawToVa(pe.FindCode(code));
            if (offset187 == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var edx169 = (offset187 ^ 0x4955C327).PackToHex(4);

            code = "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC 24 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B 45 08 8B C8";
            var offset19f = pe.RawToVa(pe.FindCode(code));
            if (offset19f == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var ecx190 = (offset19f ^ 0x4955C327).PackToHex(4);

            code = "55 8B EC 51 68 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B F0 85 F6 0F 84 ?? ?? ?? ?? 57 8B 7D 08 85 FF 74 ?? 66 0F 1F 44 00 00 85 F6 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 8B F0 83 EF 01 75 E5 85 C0 0F 84 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 04";
            var offset1bc = pe.RawToVa(pe.FindCode(code));
            if (offset1bc == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }
            var eax1a4 = (offset1bc ^ 0x4955C327).PackToHex(4);

            var ecx060 = (0x1D657B56 ^ pe.RawToVa(start + 1)).PackToHex(4);

            code = "68 " + pe.StringVa("XMLDocument").PackToHex(4) + " B9 ?? ?? ?? ??"; // ?? ?? ?? ??
            var offsetxml = pe.FindCode(code) + 6;
            if (offsetxml == -1)
            {
                ShowErrorWindow("Failed RestoreClientinfoxml.", "Error : " + name);
                return false;
            }

            var ecx0dc = ((int)(pe.FetchDWord(offsetxml) ^ 0xB0414DA7)).PackToHex(4);

            // No Address Port
            var eax35f = ((int)(clientInfoAddr ^ 0xC66FFB92)).PackToHex(4);
            var ecx36b = ((int)(clientInfoPort ^ 0xC7C470EF)).PackToHex(4);
            var ecx378 = ((int)((clientInfoPort + 4) ^ 0x7C0D0386)).PackToHex(4);

            var ecx485 = (0x4E5E33E ^ snprintf).PackToHex(4);

            code = "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC 84 00 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B F9 8B 75 08";
            var offset4c6 = pe.RawToVa(pe.FindCode(code));

            var eax4b0 = ((int)(0x4E5E33E ^ offset4c6)).PackToHex(4);

            code = "55 8B EC 83 EC 14 A1 ?? ?? ?? ?? 33 C5 89 45 FC E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 14";
            var push64c = pe.RawToVa(pe.FindCode(code)).PackToHex(4);

            code = "00 B1 8A B6 9E B5 90 50 F7 40 86 F9 D8 0C 31 78 00 " + // Data 
                   "51 " +                      // push ecx     Load Clientinfo.xml 함수 시작   // start + 0x11
                   "E8 06 00 00 00 " +          // call #1   --->---
                   "59 " +                      // pop ecx    <----|-------<------------<-------| call # 1 리턴
                   "E9 1C 03 00 00 " +          // jmp 2336339  ---|----------->------->---|    |
                   "55 " +                      // push ebp  <------                       |    |
                   "53 " +                      // push ebx                                |    |
                   "57 " +                      // push edi                                |    |
                   "56 " +                      // push esi                                |    |
                   "83 EC 6C " +                // sub esp, 6c                             |    |
                   "A1 " + obp1cd + " " +       // mov eax,dword ptr ds:[0x023361CD]       |    |     
                   "A3 " + obp1c9 + " " +       // mov dword ptr ds:[0x023361C9],eax       |    |     
                   "B9 00 00 00 00 " +          // mov ecx,0                               |    |
                   "89 4C 24 08 " +             // mov dword ptr ss:[esp+8],ecx            |    |
                   "BA " + edx037 + " " +       // mov edx,49005D87                        |    |  037
                   "33 D0 " +                   // xor edx,eax                             |    |
                   "8D 4C 24 30 " +             // lea ecx,dword ptr ss:[esp+30]           |    |
                   "FF D2 " +                   // call edx                                |    |  call+042  559EA0
                   "B8 00 00 00 00 " +          // mov eax,0                               |    |
                   "8B E8 " +                   // mov ebp,eax                             |    |
                   "8D 88 23 01 00 00 " +       // lea ecx,dword ptr ds:[eax+123]          |    |
                   "89 4C 24 0C " +             // mov dword ptr ss:[esp+c],ecx            |    |
                   "BF " + edi055 + " " +       // mov edi, 49006417                       |    |  055
                   "33 3D " + obp1c9 + " " +    // xor edi,dword ptr ds:[0x023361C9]       |    |
                   "B9 " + ecx060 + " " +       // mov ecx,1F561B57                        |    |  060
                   "81 F1 56 7B 65 1D " +       // xor ecx,1D657B56                        |    |   
                   "33 DB " +                   // xor ebx,ebx                             |    |
                   "33 D2 " +                   // xor edx,edx                             |    |
                   "8A 04 11 " +                // mov al,byte ptr ds:[ecx+edx]            |    |
                   "32 C3 " +                   // xor al,bl                               |    |
                   "2A D8 " +                   // sub bl,al                               |    |
                   "80 F3 7B " +                // xor bl,7B                               |    |
                   "34 D2 " +                   // xor al,D2                               |    |
                   "88 82 " + obp235 + " " +    // mov byte ptr ds:[edx+2336235],al        |    |
                   "8D 52 01 " +                // lea edx,dword ptr ds:[edx+1]            |    |
                   "75 E9 " +                   // jne 233606F                             |    |
                   "8B 74 24 08 " +             // mov esi,dword ptr ss:[esp+8]            |    |
                   "B9 DE 00 00 00 " +          // mov ecx,DE                              |    |
                   "03 4C 24 0C " +             // add ecx,dword ptr ss:[esp+C]            |    |
                   "8B C5 " +                   // mov eax,ebp                             |    |
                   "33 F5 " +                   // xor esi,ebp                             |    |
                   "33 CD " +                   // xor ecx,ebp                             |    |
                   "33 44 24 08 " +             // xor eax,dword ptr ss:[esp+8]            |    |
                   "0F BE C0 " +                // movsx eax,al                            |    |
                   "0F BE D1 " +                // movsx edx,cl                            |    |
                   "8D 4C 24 30 " +             // lea ecx,dword ptr ss:[esp+30]           |    |
                   "50 " +                      // push eax                                |    |
                   "52 " +                      // push edx                                |    |
                   "56 " +                      // push esi                                |    |
                   "68 " + push235 + " " +      // push 2336235                            |    |   0aa
                   "FF D7 " +                   // call edi                                |    |   call+0AF 55A730
                   "84 C0 " +                   // test al,al                              |    |
                   "0F 84 85 00 00 00 " +       // je 233613E                              |    |
                   "C7 44 24 10 15 55 26 63 " + // mov dword ptr ss:[esp+10],63265515      |    |
                   "C7 44 24 14 BB A5 ED 69 " + // mov dword ptr ss:[esp+14],69EDA5BB      |    | 
                   "BA " + edx0c9 + " " +       // mov edx,49F797D7                        |    |  0c9
                   "33 15 " + obp1c9 + " " +    // xor edx,dword ptr ds:[23361C9]          |    |
                   "C7 44 24 18 56 A0 71 FD " + // mov dword ptr ss:[esp+18],FD71A056      |    |
                   "B9 " + ecx0dc + " " +       // mov ecx,B10FBC0B                        |    |   0dc
                   "81 F1 A7 4D 41 B0 " +       // xor ecx,B0414DA7                        |    |
                   "8D 74 24 30 " +             // lea esi,dword ptr ss:[esp+30]           |    |
                   "8B 46 08 " +                // mov eax,dword ptr ds:[esi+8]            |    |
                   "8B 7E 10 " +                // mov edi,dword ptr ds:[esi+10]           |    |
                   "03 F8 " +                   // add edi,eax                             |    |
                   "83 EC 08 " +                // sub esp,8                               |    |
                   "57 " +                      // push edi                                |    |
                   "50 " +                      // push eax                                |    |
                   "FF D2 " +                   // call edx                                |    |  call+0F8 A254F0
                   "83 C4 08 " +                // add esp,8                               |    |
                   "B8 " + eax0fd + " " +       // mov eax,49005C37                        |    |  0fd
                   "33 05 " + obp1c9 + " " +    // xor eax,dword ptr ds:[23361C9]          |    |
                   "8B CE " +                   // mov ecx,esi                             |    |
                   "FF D0 " +                   // call eax                                |    |  call+10A 559F10
                   "0F B6 05 " + obp1d1 + " " + // movzx eax,byte ptr ds:[23361D1]         |    |
                   "83 F0 71 " +                // xor eax,71                              |    |
                   "33 C9 " +                   // xor ecx,ecx                             |    |
                   "33 D2 " +                   // xor edx,edx                             |    |
                   "42 " +                      // inc edx                                 |    |
                   "33 F6 " +                   // xor esi,esi                             |    |
                   "3B C6 " +                   // cmp eax,esi                             |    |
                   "74 30 " +                   // je 2336151                              |    |
                   "83 FA 64 " +                // cmp edx,64                              |    |
                   "0F 43 D1 " +                // cmovae edx,ecx                          |    |
                   "8A 5C 34 11 " +             // mov bl,byte ptr ss:[esp+esi+11]         |    |
                   "32 9A " + obp1d1 + " " +    // xor bl,byte ptr ds:[edx+23361D1]        |    |
                   "80 F3 64 " +                // xor bl,64                               |    |
                   "88 9E " + obp235 + " " +    // mov byte ptr ds:[esi+2336235],bl        |    |
                   "42 " +                      // inc edx                                 |    |
                   "46 " +                      // inc esi                                 |    |
                   "EB DF " +                   // jmp 233611D                             |    |
                   "B8 " + eax0fd + " " +       // mov eax,49005C37                        |    |
                   "33 05 " + obp1c9 + " " +    // xor eax,dword ptr ds:[23361C9]          |    |
                   "8D 4C 24 30 " +             // lea ecx,dword ptr ss:[esp+30]           |    |
                   "FF D0 " +                   // call eax                                |    |  call+14D 559F10
                   "EB 70 " +                   // jmp 23361C1                             |    |
                   "C6 80 " + obp235 + " 00 " + // mov byte ptr ds:[eax+2336235],0         |    |
                   "33 C0 " +                   // xor eax,eax                             |    |
                   "8A 88 " + obp235 + " " +    // mov cl,byte ptr ds:[eax+2336235]        |    |
                   "88 4C 04 1C " +             // mov byte ptr ss:[esp+eax+1C],cl         |    |
                   "40 " +                      // inc eax                                 |    |
                   "84 C9 " +                   // test cl,cl                              |    |
                   "75 F1 " +                   // jne 233615A                             |    |
                   "BA " + edx169 + " " +       // mov edx,49F78D87                        |    |  169
                   "33 15 " + obp1c9 + " " +    // xor edx,dword ptr ds:[23361C9]          |    |
                   "B9 " + ecx0dc + " " +       // mov ecx,B10FBC0B                        |    |  174
                   "81 F1 A7 4D 41 B0 " +       // xor ecx,B0414DA7                        |    |
                   "83 EC 0C " +                // sub esp,C                               |    |
                   "8D 44 24 28 " +             // lea eax,dword ptr ss:[esp+28]           |    |
                   "50 " +                      // push eax                                |    |
                   "FF D2 " +                   // call edx                                |    |  call+187  A24EA0
                   "83 C4 0C " +                // add esp,C                               |    |
                   "85 C0 " +                   // test eax,eax                            |    |
                   "74 31 " +                   // je 23361C1                              |    |
                   "B9 " + ecx190 + " " +       // mov ecx,49F5D837                        |    |  190
                   "33 0D " + obp1c9 + " " +    // xor ecx,dword ptr ds:[23361C9]          |    |
                   "83 EC 0C " +                // sub esp,C                               |    |
                   "50 " +                      // push eax                                |    |
                   "FF D1 " +                   // call ecx                                |    |  call+19F  A01B10  190
                   "83 C4 10 " +                // add esp,10                              |    |
                   "B8 " + eax1a4 + " " +       // mov eax,49F5D587                        |    |  1A4
                   "33 05 " + obp1c9 + " " +    // xor eax,dword ptr ds:[23361C9]          |    |
                   "B9 00 00 00 00 " +          // mov ecx,0                               |    |
                   "33 4C 24 08 " +             // xor ecx,dword ptr ss:[esp+8]            |    |
                   "83 EC 0C " +                // sub esp,C                               |    |
                   "51 " +                      // push ecx                                |    |
                   "FF D0 " +                   // call eax                                |    |  call+1BC  A016A0 1A4
                   "83 C4 10 " +                // add esp,10                              |    |
                   "83 C4 6C " +                // add esp,6C                              |    |
                   "5E " +                      // pop esi                                 |    |
                   "5F " +                      // pop edi                                 |    |
                   "5B " +                      // pop ebx                                 |    |
                   "5D " +                      // pop ebp                                 |    |
                   "C3 " +                      // ret  ------->------------------>-------------|
                   "00 00 00 00 " +                                        //=========     |
                   "27 C3 55 49 7B 52 2E 6E BA AF FD 64 5C A2 7A 99 " +    // Data Area    |
                   "BB D4 AD 94 3A FB 38 58 F8 4A 4B 68 19 97 50 08 92 " + //              |
                   "76 F1 0C C4 72 67 91 E7 7D 49 FC A3 2C A7 2D E2 0D " + //              |
                   "10 BD A6 57 54 DC 6F 56 03 27 DE E1 B8 F4 AC B0 37 " + //              |
                   "30 89 F0 1F B7 5F 01 7C A1 C0 D8 3B D1 AB 8E 1B 36 " + //              |
                   "35 D0 8C EF D5 7F 13 53 4F 0A 78 9F 33 EB 14 11 81 " + //              |
                   "0E CD 02 " +                                           //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +          //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //              |
                   "00 00 00 00 00 00 00 00 " +   // ==============================        |
                   "E9 FB 02 00 00 00 " +         // jmp       <---------------------------|->--|
                   "25 73 3A 25 73 00 00 " +      // %s:%s                                      | // start + 0x33F
                   "55 " +                        // push ebp : No Address Port Start           | // start + 0x346
                   "53 " +                        // push ebx                                   |
                   "57 " +                        // push edi                                   |
                   "56 " +                        // push esi                                   |
                   "83 EC 1C " +                  // sub esp,1C                                 |
                   "89 4C 24 14 " +               // mov dword ptr ss:[esp+14],ecx              |
                   "8B 74 24 30 " +               // mov esi,dword ptr ss:[esp+30]              |
                   "A1 " + obp4cc + " " +         // mov eax,dword ptr ds:[23364CC]             |  
                   "A3 " + obp4c8 + " " +         // mov dword ptr ds:[23364C8],eax             |
                   "B8 " + eax35f + " " +         // mov eax,C77942DE                           |  35f
                   "35 92 FB 6F C6 " +            // xor eax,C66FFB92                           |  clientinfo addr
                   "8B 00 " +                     // mov eax,dword ptr ds:[eax]                 |
                   "B9 " + ecx36b + " " +         // mov ecx,C6D2C9BF                           |  36b
                   "81 F1 EF 70 C4 C7 " +         // xor ecx,C7C470EF                           |  clientinfo port
                   "8B 19 " +                     // mov ebx,dword ptr ds:[ecx]                 |
                   "B9 " + ecx378 + " " +         // mov ecx,7D1BBAD2                           |  378
                   "81 F1 86 03 0D 7C " +         // xor ecx,7C0D0386                           |  addr:port  [port +4]
                   "8B 09 " +                     // mov ecx,dword ptr ds:[ecx]                 |
                   "89 4C 24 0C " +               // mov dword ptr ss:[esp+C],ecx               |
                   "33 C9 " +                     // xor ecx,ecx                                |
                   "8A 14 08 " +                  // mov dl,byte ptr ds:[eax+ecx]               |
                   "88 14 0E " +                  // mov byte ptr ds:[esi+ecx],dl               |
                   "41 " +                        // inc ecx                                    |
                   "84 D2 " +                     // test dl,dl                                 |
                   "75 F5 " +                     // jne 233638B                                |
                   "89 74 24 10 " +               // mov dword ptr ss:[esp+10],esi              |
                   "C7 44 24 18 1D 13 39 0A " +   // mov dword ptr ss:[esp+18],A39131D          |
                   "8D 7B FF " +                  // lea edi,dword ptr ds:[ebx-1]               |
                   "33 ED " +                     // xor ebp,ebp                                |
                   "4D " +                        // dec ebp                                    |
                   "BA 13 00 80 00 " +            // mov edx,800013                             |
                   "33 F6 " +                     // xor esi,esi                                |
                   "85 ED " +                     // test ebp,ebp                               |
                   "74 18 " +                     // je 23363CB                                 |
                   "8A 03 " +                     // mov al,byte ptr ds:[ebx]                   |
                   "8B C8 " +                     // mov ecx,eax                                |
                   "80 C1 F7 " +                  // add cl,F7                                  |
                   "80 F9 17 " +                  // cmp cl,17                                  |
                   "77 1A " +                     // ja 23363D9                                 |
                   "0F B6 C9 " +                  // movzx ecx,cl                               |
                   "0F A3 CA " +                  // bt edx,ecx                                 |
                   "73 12 " +                     // jae 23363D9                                |
                   "43 " +                        // inc ebx                                    |
                   "4D " +                        // dec ebp                                    |
                   "EB E4 " +                     // jmp 23363AF                                |
                   "33 ED " +                     // xor ebp,ebp                                |
                   "C7 44 24 08 00 00 00 00 " +   // mov dword ptr ss:[esp+8],0                 |
                   "8B DF " +                     // mov ebx,edi                                |
                   "EB 1F " +                     // jmp 23363F8                                |
                   "3C 2B " +                     // cmp al,2B                                  |
                   "74 04 " +                     // je 23363E1                                 |
                   "3C 2D " +                     // cmp al,2D                                  |
                   "75 0F " +                     // jne 23363F0                                |
                   "33 C9 " +                     // xor ecx,ecx                                |
                   "3C 2D " +                     // cmp al,2D                                  |
                   "0F 94 C1 " +                  // sete cl                                    |
                   "89 4C 24 08 " +               // mov dword ptr ss:[esp+8],ecx               |
                   "43 " +                        // inc ebx                                    |
                   "4D " +                        // dec ebp                                    |
                   "EB 08 " +                     // jmp 23363F8                                |
                   "C7 44 24 08 00 00 00 00 " +   // mov dword ptr ss:[esp+8],0                 |
                   "33 FF " +                     // xor edi,edi                                |
                   "33 C0 " +                     // xor eax,eax                                |
                   "3B EF " +                     // cmp ebp,edi                                |
                   "74 38 " +                     // je 2336438                                 |
                   "0F BE 14 3B " +               // movsx edx,byte ptr ds:[ebx+edi]            |
                   "8D 4A D0 " +                  // lea ecx,dword ptr ds:[edx-30]              |
                   "83 F9 0A " +                  // cmp ecx,A                                  |
                   "72 1A " +                     // jb 2336426                                 |
                   "8D 4A BF " +                  // lea ecx,dword ptr ds:[edx-41]              |
                   "83 F9 1A " +                  // cmp ecx,1A                                 |
                   "72 24 " +                     // jb 2336438                                 |
                   "8D 4A 9F " +                  // lea ecx,dword ptr ds:[edx-61]              |
                   "83 F9 19 " +                  // cmp ecx,19                                 |
                   "77 1C " +                     // ja 2336438                                 |
                   "83 C2 A9 " +                  // add edx,FFFFFFA9                           |
                   "8B CA " +                     // mov ecx,edx                                |
                   "83 FA 09 " +                  // cmp edx,9                                  |
                   "77 12 " +                     // ja 2336438                                 |
                   "68 0A 00 00 00 " +            // push A                                     |
                   "5A " +                        // pop edx                                    |
                   "F7 E2 " +                     // mul edx                                    |
                   "6B F6 0A " +                  // imul esi,esi,A                             |
                   "03 C1 " +                     // add eax,ecx                                |
                   "13 F2 " +                     // adc esi,edx                                |
                   "47 " +                        // inc edi                                    |
                   "EB C4 " +                     // jmp 23363FC                                |
                   "8B C8 " +                     // mov ecx,eax                                |
                   "F7 D9 " +                     // neg ecx                                    |
                   "83 7C 24 08 00 " +            // cmp dword ptr ss:[esp+8],0                 |
                   "0F 44 C8 " +                  // cmove ecx,eax                              |
                   "8B 6C 24 10 " +               // mov ebp,dword ptr ss:[esp+10]              |
                   "89 4D 10 " +                  // mov dword ptr ss:[ebp+10],ecx              |
                   "A1 " + obp4c8 + " " +         // mov eax,dword ptr ds:[23364C8]             |
                   "0F B6 15 " + obp4d0 + " " +   // movzx edx,byte ptr ds:[23364D0]            |
                   "83 F2 79 " +                  // xor edx,79                                 |
                   "33 F6 " +                     // xor esi,esi                                |
                   "33 FF " +                     // xor edi,edi                                |
                   "47 " +                        // inc edi                                    |
                   "33 DB " +                     // xor ebx,ebx                                |
                   "3B D3 " +                     // cmp edx,ebx                                |
                   "74 1D " +                     // je 2336482                                 |
                   "83 FF 64 " +                  // cmp edi,64                                 |
                   "0F 43 FE " +                  // cmovae edi,esi                             |
                   "8A 4C 1C 19 " +               // mov cl,byte ptr ss:[esp+ebx+19]            |
                   "32 8F " + obp4d0 + " " +      // xor cl,byte ptr ds:[edi+23364D0]           |
                   "80 F1 64 " +                  // xor cl,64                                  |
                   "88 8B " + obp534 + " " +      // mov byte ptr ds:[ebx+<2336534>],cl         |
                   "47 " +                        // inc edi                                    |
                   "43 " +                        // inc ebx                                    |
                   "EB DF " +                     // jmp 2336461                                |
                   "83 C5 14 " +                  // add ebp,14                                 |
                   "B9 " + ecx485 + " " +         // mov ecx,4BDA36E                            |  485
                   "33 C1 " +                     // xor eax,ecx                                |
                   "B9 " + obp534 + " " +         // mov 2336534                                |  48c
                   "C6 82 " + obp534 + " 00 " +   // mov byte ptr ds:[edx+2336534>],0           |
                   "83 EC 0C " +                  // sub esp,C                                  |
                   "FF 74 24 18 " +               // push dword ptr ss:[esp+18]                 |
                   "51 " +                        // push ecx                                   |
                   "68 FF FF FF FF " +            // push FFFFFFFF                              |
                   "68 81 00 00 00 " +            // push 81                                    |
                   "55 " +                        // push ebp                                   |
                   "FF D0 " +                     // call eax                                   |  call+4AB 584050 vsnprintf_s
                   "83 C4 20 " +                  // add esp,20                                 |
                   "B8 " + eax4b0 + " " +         // mov eax,45FF9FE                            |   4b0 eax
                   "33 05 " + obp4c8 + " " +      // xor eax,dword ptr ds:[23364C8]             |
                   "8B 4C 24 14 " +               // mov ecx,dword ptr ss:[esp+14]              |
                   "83 C4 1C " +                  // add esp,1C                                 |
                   "5E " +                        // pop esi                                    |
                   "5F " +                        // pop edi                                    |
                   "5B " +                        // pop ebx                                    |
                   "5D " +                        // pop ebp                                    |
                   "FF E0 " +                     // jmp eax                                    | jmp+4C6  BA1AC0
                   "00 00 00 00 " +               // ===================================        |
                   "3E E3 E5 04 7B 52 2E 6E BA AF FD 64 5C A2 " +          // Data Area         |
                   "7A 99 BB D4 AD 94 3A FB 38 58 F8 4A 4B 68 19 97 50 " + //                   |
                   "08 92 76 F1 0C C4 72 67 91 E7 7D 49 FC A3 2C A7 2D " + //                   |
                   "E2 0D 10 BD A6 57 54 DC 6F 56 03 27 DE E1 B8 F4 AC " + //                   |
                   "B0 37 30 89 F0 1F B7 5F 01 7C A1 C0 D8 3B D1 AB 8E " + //                   |
                   "1B 36 35 D0 8C EF D5 7F 13 53 4F 0A 78 9F 33 EB 14 " + //                   |
                   "11 81 0E CD 02 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + //                   |
                   "00 00 00 00 00 00 00 00 00 00 00 " +                   //                   |
                   "51 " +                 // push ecx  <---------------------------------------|
                   "E8 00 00 00 00 " +     // call #2 -----|                                          
                   "59 " +                 // pop ecx  <---|
                   "83 C1 13 " +           // add ecx,13
                   "FF 74 24 08 " +        // push dword ptr ss:[esp+8]
                   "51 " +                 // push ecx
                   "8B 4C 24 08 " +        // mov ecx,dword ptr ss:[esp+8]
                   "68 " + push64c + " " + // push      Server Address Port 함수주소로            // push+64C 0xA00000
                   "C3 " +                 // ret       리턴
                   "83 C4 04 " +           // add esp,4 <-- Server Address Port 종료후 시작위치    // call #2 반환
                   "59 " +                 // pop ecx
                   "EB 02 " +              // jmp 
                   "00 00 " +              //
                   "C2";                   // ret 0 리턴 (Clientinfo.xml 읽기 함수 종료)

            //pe.ReplaceHex(start, code);
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool EnableMultipleGRF(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0x700;

            string datagrf = pe.StringVa("data.grf").PackToHex(4);

            string code = "B9 ?? ?? ?? ?? " +     // mov ecx, getEcxFileMgrHex
                          "68 " + datagrf + " " + // push "datagrf"
                          "E8 " + "?? ?? ?? ??";  // call addpackOffset

            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                MessageBox.Show("Not Found addpackOffset", "Error : " + name);
                return false;
            }

            var addpack = pe.FetchDWord(offset + 11) + pe.RawToVa(offset + 10) + 5; //  call 실제 주소(VA)
            addpack = pe.VaToRaw(addpack); //Raw주소로 변환

            string getEcxFileMgrHex = pe.FetchDWord(pe.FindCode(code) + 1).PackToHex(4);
            //pe.ReplaceByte(offset + 5, 0xB9); // push -> mov ecx (68 -> B9)
            //pe.ReplaceHex(offset + 11, pe.CallOffset(start, offset + 10));
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 5,
                Hex = "B9"
            };
            Patchs.Add(patch);
            patch = new Patch
            {
                Offset = offset + 11,
                Hex = pe.CallOffset(start, offset + 10)
            };
            Patchs.Add(patch);

            int GetModuleHandleARaw = pe.FindFunctionAddress("kernel32.dll", "GetModuleHandleA");
            int GetModuleHandleAVa = pe.RawToVa(GetModuleHandleARaw);
            string GetModuleHandleA = GetModuleHandleAVa.PackToHex(4);

            int GetProcAddressRaw = pe.FindFunctionAddress("kernel32.dll", "GetProcAddress");
            int GetProcAddressVa = pe.RawToVa(GetProcAddressRaw);
            string GetProcAddress = GetProcAddressVa.PackToHex(4);

            string kernel32 = pe.RawToVa(start + 0xab).PackToHex(4);
            string GetStringA = pe.RawToVa(start + 0xb4).PackToHex(4);
            string WriteStringA = pe.RawToVa(start + 0xcd).PackToHex(4);
            string DATAINI = pe.RawToVa(start + 0xed).PackToHex(4);
            string DATA = pe.RawToVa(start + 0xe8).PackToHex(4);
            string addpackOffset = pe.CallOffset(addpack, start + 0x73);

            code =
                "C8 80 00 00 " +                    // enter 80,0
                "60 " +                             // pushad
                "68 " + kernel32 + " " +            // push "kernel32"
                "FF 15 " + GetModuleHandleA + " " + // call dword ptr ds:[<GetModuleHandleA>] 
                "85 C0 " +                          // test eax,eax    
                "74 23 " +                          // je short  --------------------------------
                "8B 3D " + GetProcAddress + " " +   // mov edi,dword ptr ds:[<GetProcAddress>]  |
                "68 " + GetStringA + " " +          // push "GetPrivateProfileStringA"          |
                "89 C3 " +                          // mov ebx,eax                              |
                "50 " +                             // push eax                                 |
                "FF D7 " +                          // call edi                                 |
                "85 C0 " +                          // test eax,eax                             |
                "74 0F " +                          // je short  -------------------->----------|---
                "89 45 F6 " +                       // mov dword ptr ss:[ebp-A],eax             |  | 
                "68 " + WriteStringA + " " +        // push "WritePrivateProfileStringA"        |  |
                "89 D8 " +                          // mov eax,ebx                              |  |
                "50 " +                             // push eax                                 |  |
                "FF D7 " +                          // call edi                                 |  |
                "85 C0 " +                          // test eax,eax                             |  |
                "74 6E " +                          // je  short   <---------------------<------------    
                "89 45 FA " +                       // mov dword ptr ss:[ebp-6],eax                  |
                "31 D2 " +                          // xor edx,edx                                   |
                "66 C7 45 FE 39 00 " +              // mov word ptr ss:[ebp-2],39 ; 39: '9'  <-------|-----
                "52 " +                             // push edx                                      |    |
                "68 " + DATAINI + " " +             // push ".\\DATA.INI"                            |    |
                "6A 74 " +                          // push 74                                       |    |
                "8D 5D 81 " +                       // lea ebx,dword ptr ss:[ebp-7F]                 |    |
                "53 " +                             // push ebx                                      |    |
                "8D 45 FE " +                       // lea eax,dword ptr ss:[ebp-2]                  |    |
                "50 " +                             // push eax                                      |    |
                "50 " +                             // push eax                                      |    |
                "68 " + DATA + " " +                // push "Data"                                   |    |
                "FF 55 F6 " +                       // call dword ptr ss:[ebp-A]                     |    |
                "8D 4D FE " +                       // lea ecx,dword ptr ss:[ebp-2]                  |    |
                "66 8B 09 " +                       // mov cx,word ptr ds:[ecx]                      |    |
                "8D 5D 81 " +                       // lea ebx,dword ptr ss:[ebp-7F]                 |    |
                "66 3B 0B " +                       // cmp cx,word ptr ds:[ebx]                      |    |
                "5A " +                             // pop edx                                       |    |
                "74 0E " +                          // je    -----------------------                 |    |
                "52 " +                             // push edx                     |                |    |
                "53 " +                             // push ebx                     |                |    |
                "B9 " + getEcxFileMgrHex + " " +    // mov ecx, getEcxFileMgrHex    |                |    |
                "E8 " + addpackOffset + " " +       // call  addpackOffset          |                |    |
                "5A " +                             // pop edx                      |                |    |
                "42 " +                             // inc edx                      |                |    |
                "FE 4D FE " +                       // dec byte ptr ss:[ebp-2] <----                 |    |
                "80 7D FE 30 " +                    // cmp byte ptr ss:[ebp-2],30                    |    |
                "73 C1 " +                          // jae                                           |    |
                "85 D2 " +                          // test edx,edx                                  |    |
                "75 20 " +                          // jne                                           |    |
                "68 " + DATAINI + " " +             // push ".\\DATA.INI"                            |    |
                "68 " + datagrf + " " +             // push "data.grf"                               |    |
                "66 C7 45 FE 32 00 " +              // mov word ptr ss:[ebp-2],32                    |    |
                "8D 45 FE " +                       // lea eax,dword ptr ss:[ebp-2]                  |    |
                "50 " +                             // push eax                                      |    |
                "68 " + DATA + " " +                // push "Data"                                   |    |
                "FF 55 FA " +                       // call                                          |    |
                "85 C0 " +                          // text eax,eax                                  |    |
                "75 97 " +                          // jne      -------------------------------------|-----
                "61 " +                             // popad    <------------------------------------|
                "C9 " +                             // leave
                "C3 00 " +                          // ret + null(00)
                "4B 45 52 4E 45 4C 33 32 00 " +     // "KERNEL32"
                "47 65 74 50 72 69 76 61 74 65 50 72 6F 66 69 6C 65 53 74 72 69 6E 67 41 00 " + // "GetPrivateP:rofilesStringA"
                "57 72 69 74 65 50 72 69 76 61 74 65 50 72 6F 66 69 6C 65 53 74 72 69 6E 67 41 00 " + // "WritePrivateProfileStringA"
                "44 61 74 61 00 " + // "Data"
                "2E 5C 44 41 54 41 2E 49 4E 49 00"; // ".\DATA.INI"

            //pe.ReplaceHex(start, code);
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool EnableDNSSuport(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0x800;
            var ipAddr = pe.RawToVa(start).PackToHex(4);

            var port = pe.StringVa("port").PackToHex(4);
            var code = "68 " + port + " " +  // push "port"
                       "8B ?? " +            // mov ecx,??
                       "E8";                 // call addr -> call start+70
            var addrs = pe.FindCodes(code);
            if (addrs.Count == 0)
            {
                ShowErrorWindow("Port string not found", "Error : " + name);
                return false;
            }

            var callport = pe.FetchDWord(addrs[0] + 8) + pe.RawToVa(addrs[0] + 7) + 5; // call Va주소
            var jmpport = pe.CallOffset(pe.VaToRaw(callport), start + 0x75);

            for (int i = 0; i < addrs.Count; i++)
            {
                string calloffset = pe.CallOffset(start + 0x70, addrs[i] + 7);
                pe.ReplaceHex(addrs[i] + 8, calloffset); // call start+0x70
            }

            var ws2_32dll = pe.StringVa("ws2_32.dll").PackToHex(4);
            code = "68 " + ws2_32dll + " " + // push "ws2_32.dll"
                   "FF D3";                  // call ebx
            var jmpaddr = pe.FindCode(code);
            var retaddr = pe.RawToVa(jmpaddr + 5).PackToHex(4);

            if (jmpaddr == -1)
            {
                ShowErrorWindow("Find not Jump Address", "Error : " + name);
                return false;
            }
            string jmpoffset = pe.CallOffset(start + 0x80, jmpaddr);
            //pe.ReplaceHex(jmpaddr, "E9 " + jmpoffset);   // push addr -> jmp start+0x80
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = jmpaddr,
                Hex = "E9 " + jmpoffset
            };
            Patchs.Add(patch);

            var straccout = pe.StringVa("211.172.247.115");
            code = "C7 05 ?? ?? ?? ?? " + straccout.PackToHex(4);
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Account Address assignment not found", "Error : " + name);
                return false;
            }
            var accountAddr = pe.FetchDWord(offset + 2).PackToHex(4);

            var gethostbyname = pe.RawToVa(pe.FindFunctionAddress("ws2_32.dll", "gethostbyname")).PackToHex(4);
            var wsprintfA = pe.RawToVa(pe.FindFunctionAddress("user32.dll", "wsprintfA")).PackToHex(4);

            var ipForamt = pe.StringVa("%d.%d.%d.%d").PackToHex(4);

            code = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " + // ipaddr  //start
                   "60 " +                                        // pushad     // start + 0x20
                   "8B 35 " + accountAddr + " " +                 // mov esi, dword ptr ds:[accountAddr]
                   "56 " +                                        // push esi     
                   "FF 15 " + gethostbyname + " " +               // call dword ptr ds:[gethostbyname]
                   "85 C0 " +                                     // test eax,eax
                   "75 02 " +                                     // jne short
                   "61 " +                                        // popad
                   "C3 " +                                        // ret
                   "8B 48 0C 8B 11 8B C2 0F B6 48 03 51 0F B6 48 02 51 0F B6 48 01 51 0F B6 08 51 " +
                   "68 " + ipForamt + " " +                       // push %d.%d.%d.%d
                   "68 " + ipAddr + " " +                         // push ipAddr      // start
                   "FF 15 " + wsprintfA + " " +                   // call dword ptr ds:[wsprintfA]
                   "83 C4 18 " +                                  // add esp, 18
                   "C7 05 " + accountAddr + " " + ipAddr + " " +  // mov dword ptr ds:[accountAddr], ipaddr
                   "61 " +                                        // popad
                   "C3 " +                                        // ret
                   "00 00 00 " +                                  // null
                   "E8 AB FF FF FF " +                            // call start+0x20   //start + 0x70
                   "E9 " + jmpport + " " +                        // jmp jmpport       //start + 0x75
                   "00 00 00 00 00 00 " +                         // null
                   "68 " + ws2_32dll + " " +                      // push "ws2_32.dll"
                   "68 " + retaddr + " " +                        // push retaddr      //start + x80
                   "E9 91 FF FF FF";                              // jmp start+0x20

            //pe.ReplaceHex(start, code);
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool DisableIndoorRSW(int id, string name)
        {
            var code = "69 6E 64 6F 6F 72 52 73 77 54 61 62 6C 65 2E 74 78 74";
            var offset = pe.FindCode(code, 0, pe.Buffer.Length);
            if (offset == -1)
            {
                ShowErrorWindow("Failed DisableIndoorRSW", "Error : " + name);
                return false;
            }
            //pe.ReplaceByte(offset, 0x00);
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset,
                Hex = "00"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool FixCameraAngles(int id, string name)
        {
            var code = "74 ?? F3 0F 10 15 ?? ?? ?? ??";
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed Fix Camera Angles.", "Error : " + name);
                return false;
            }
            var addr = pe.FetchDWord(offset + 6);
            var addrRaw = pe.VaToRaw(addr);

            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch();
            switch (id)
            {
                case 19: // Custom
                    code = OneTextBoxWindow("Number Input", "Input Max camera angle(20-65, deault:20, less:29.5, recommended:42, full:65)", "20");

                    if (code == null || float.Parse(code) < 20 ||  float.Parse(code) > 65 || !float.TryParse(code, out _))
                    {
                        ShowErrorWindow("Patch Error", "Patch Canceled.");
                        return false;
                    }
                    byte[] bytes = BitConverter.GetBytes(float.Parse(code));
                    string result = BitConverter.ToString(bytes).Replace("-", " ");
                    patch = new Patch
                    {
                        Offset = addrRaw,
                        Hex = result
                    };
                    break;
                case 20: // Full
                    patch = new Patch
                    {
                        Offset = addrRaw,
                        Hex = "00 00 82 42"
                    };
                    break;
                case 21: // Less
                    patch = new Patch
                    {
                        Offset = addrRaw,
                        Hex = "00 00 EC 41"
                    };
                    break;
                case 22: // Recommended
                    patch = new Patch
                    {
                        Offset = addrRaw,
                        Hex = "00 00 28 42"
                    };
                    break;
            }

            //pe.ReplaceHex(addr, "00 00 0C 42");

            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool RestoreRoulette(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0x900;
            var code = "B9 ?? ?? ?? ?? " +        //mov ecx,addr1
                       "E8 ?? ?? ?? ?? " +        //call addr
                       "80 3D ?? ?? ?? ?? 00 " +  //cmp byte ptr ds:[],0
                       "74 ?? " +                 //je short -> jmp xxxx
                       "68 B5 00 00 00";          //push B5
            var offset = pe.FindCode(code);

            if (offset == -1)
            {
                ShowErrorWindow("Failed Restore Roulette.", "Error : " + name);
                return false;
            }

            var targetoffset = (pe.RawToVa(start) - (pe.RawToVa(offset + 17) + 5)).PackToHex(4); // jmp의 offset 값
            var value = "E9 " + targetoffset + " 90 90";

            string addr1 = pe.FetchDWord(offset + 1).PackToHex(4);
            int caller = pe.FetchDWord(offset + 6) + (offset + 5) + 5; //call addr
            string call1 = pe.CallOffset(caller, start + 0xc);
            string call2 = pe.CallOffset(caller, start + 0x1b);
            var jmptarget = pe.RawToVa(offset + 17) + 2 + pe.Buffer[offset + 18];
            var jmper = (jmptarget - pe.RawToVa(start + 0x20 + 5)).PackToHex(4);

            code = "74 0F " +            //je short
                   "68 B5 00 00 00 " +   //push B5
                   "B9 " + addr1 + " " + //mov ecx,addr1
                   "E8 " + call1 + " " + //call caller
                   "68 0C 01 00 00 " +   //push 10C
                   "B9 " + addr1 + " " + //mov ecx,addr1
                   "E8 " + call2 + " " + //call caller
                   "E9 " + jmper;        //jmp addr3

            //pe.ReplaceHex(offset + 17, value);
            //pe.ReplaceHex(start, code);
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + 17,
                Hex = value
            };
            Patchs.Add(patch);
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool ShowReplayButton(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0xA00;
            var offset = pe.StringVa(@"replay_interface\btn_replay_b");
            var code = offset.PackToHex(4);

            offset = pe.FindCode(code + " ?? ?? ?? ?? C7");
            if (offset == -1)
            {
                ShowErrorWindow("1 - OnCreate function missing", "Error : " + name);
                return false;
            }

            var offset2 = pe.FindCode("EA 00 00 00", offset, offset + 0x50);
            if (offset2 == -1)
            {
                ShowErrorWindow("2 - 2nd Button asssignment missing", "Error : " + name);
                return false;
            }

            code = "C7 45 ?? 82 00 00 00 " + // mov dword ptr ss:[],82
                   "89 45 ?? " +             // mov dword ptr ss:[],eax
                   "E8";                     // call addr
            var jmpAddr = pe.FindCode(code, offset2, offset2 + 0x50);
            if (jmpAddr == -1)
            {
                ShowErrorWindow("3 - Coordinate assignment missing", "Error : " + name);
                return false;
            }

            code = "80 3D ?? ?? ?? ?? 00 " +    // cmp byte ptr ds:[],0
                   "75 0E " +                   // jne short
                   "81 7C 85 ?? ?? 01 00 00 " + // cmp dword ptr ss:[], 
                   "0F 84";                     // je addr
            var cmpAddr = pe.FindCode(code, offset2, offset2 + 0x70);
            if (cmpAddr == -1)
            {
                ShowErrorWindow("4 - compare not found", "Error : " + name);
                return false;
            }

            //pe.ReplaceByte(cmpAddr + 7, 0xEB); // 75 -> EB  jne -> jmp
            //pe.ReplaceHex(jmpAddr + 3, "04 00 00 00"); // 82 -> 04
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = cmpAddr + 7,
                Hex = "EB"
            };
            Patchs.Add(patch);
            patch = new Patch
            {
                Offset = jmpAddr + 3,
                Hex = "04 00 00 00"
            };
            Patchs.Add(patch);

            code = "83 78 04 1E " + // cmp dword ptr ds:[],1E
                   "75";           // jne short
            offset = pe.FindCode(code, jmpAddr, jmpAddr + 0x40);
            if (offset == -1)
            {
                ShowErrorWindow("5 - compare not found", "Error : " + name);
                return false;
            }
            //pe.ReplaceByte(offset + 3, 0x6); // 1E -> 06
            patch = new Patch
            {
                Offset = jmpAddr + 3,
                Hex = "04 00 00 00"
            };
            Patchs.Add(patch);

            code = "6A 00 " +        // push 0
                   "68 29 27 00 00"; // push 2729
            offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("6 - Select Server case missing", "Error : " + name);
                return false;
            }
            offset += 7; //call addr

            code = "C6 40 ?? 01 " +        // mov byte ptr ds:[], 1
                   "33 C0 " +              // xor eax,eax
                   "C7 ?? 0C 1B 00 00 00"; // mov dword ptr ds:[],1B
            offset2 = pe.FindCode(code);
            if (offset2 == -1)
            {
                ShowErrorWindow("7 - Replay mode setter missing", "Error : " + name);
                return false;
            }
            var func = pe.RawToVa(offset2) + pe.FetchDWord(offset2 - 4); // call address
            var assigner = pe.FetchDWord(offset2).PackToHex(4).Replace("01", "00"); // "C6 40 ?? 01" -> "C6 40 ?? 00"
            //pe.ReplaceHex(offset - 5, "E9 " + (start - pe.RawToVa(offset)).PackToHex(4)); // push 2729 -> jmp start
            patch = new Patch
            {
                Offset = offset - 5,
                Hex = "E9 " + (start - pe.RawToVa(offset)).PackToHex(4)
            };
            Patchs.Add(patch);

            var GenVarHex1 = (func - (start + 6)).PackToHex(4);
            var GenVarHex2 = (pe.RawToVa(offset) - (start + 21)).PackToHex(4);

            code = "60 " +                    // pushad
                   "E8 " + GenVarHex1 + " " + // call func 
                   assigner + " " +           // mov byte ptr ds:[], 0
                   "61 " +                    // popad
                   "68 22 27 00 00 " +        // push 0x2722
                   "E9 " + GenVarHex2;        // jmp 
            //pe.ReplaceHex(start, code);
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool Enable44khzAudio(int id, string name)
        {
            var code = "C7 86 ?? ?? 00 00 40 1F 00 00 " +
                       "EB 16 " +
                       "C7 86 ?? ?? 00 00 11 2B 00 00 " +
                       "EB 0A " +
                       "C7 86 ?? ?? 00 00 22 56 00 00";
            var patchOffset = 30;
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Failed in Step 1", "Error : " + name);
                return false;
            }

            //pe.ReplaceHex(offset + patchOffset, "44 AC 00 00");
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset + patchOffset,
                Hex = "44 AC 00 00"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool Disable4LetterLimit(int id, string name)
        {
            string code;
            int offset;
            int offset2;

            code = "E8 ?? ?? ?? ?? " +  // call addr
                   "83 F8 04 " +        // cmp eax,4
                   "0F 8C ?? ?? 00 00"; // jl addr1
            var passCode = code.Replace("04", "06");
            List<Patch> Patchs = new List<Patch>();
            Patch patch;
            switch (id)
            {
                case 11:
                    ///////////////////// 캐릭터이름 4글자 제한 해제
                    var refe = pe.FindCode("68 06 0D 00 00"); // 캐릭터이름 변경 함수 메세지
                    if (refe == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - UIChangeNameWnd::SendMsg not found", "Error : " + name);
                        return false;
                    }

                    offset = pe.FindCode(code, refe, refe + 0xFF); // 캐릭터이름 체크 함수 E8 ?? ?? ?? ?? 83 F8 04 0F 8C ?? ?? 00 00
                    if (offset == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - UIChangeNameWnd::SendMsg:CharNameCheck not found", "Error : " + name);
                        return false;
                    }

                    refe = pe.FindCode("68 C7 00 00 00 E8");
                    if (refe == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - UINewMakeCharWnd::SendMsg not found", "Error : " + name);
                        return false;
                    }

                    var charcode = code.Replace("0F 8C ?? ?? 00 00", "7D ??");

                    offset2 = pe.FindCode(charcode, refe - 0x400, refe); //E8 ?? ?? ?? ?? 83 F8 04 7D ??
                    if (offset2 == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - UINewMakeCharWnd::SendMsg:CharNameCheck not found", "Error : " + name);
                        return false;
                    }

                    //pe.ReplaceByte(offset + 7, 0);// 04 -> 00
                    //pe.ReplaceByte(offset2 + 7, 0);// 04 -> 00
                    patch = new Patch
                    {
                        Offset = offset + 7,
                        Hex = "00"
                    };
                    Patchs.Add(patch);
                    patch = new Patch
                    {
                        Offset = offset2 + 7,
                        Hex = "00"
                    };
                    Patchs.Add(patch);
                    break;
                case 12:
                    //////////////////////// 패스워드 4글자 제한 해제
                    offset = pe.FindCode(passCode); // Pass check  E8 ?? ?? ?? ?? 83 F8 06 0F 8C ?? ?? 00 00
                    if (offset == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - Pass check not found.", "Error : " + name);
                        return false;
                    }
                    //pe.ReplaceByte(passOffset + 7, 0); // 06 -> 00
                    patch = new Patch
                    {
                        Offset = offset + 7,
                        Hex = "00"
                    };
                    Patchs.Add(patch);
                    break;
                case 13:
                    /////////////////////// 유저ID 4글자 제한 해제
                    offset = pe.FindCode(passCode); //E8 ?? ?? ?? ?? 83 F8 06 0F 8C ?? ?? 00 00
                    if (offset == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - Pass check not found.", "Error : " + name);
                        return false;
                    }
                    offset2 = pe.FindCode(code, offset, offset + 0xFF);
                    if (offset2 == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - ID check not found.", "Error : " + name);
                        return false;
                    }

                    code = code.Replace("0F 8C ?? ?? 00 00", "7D ??"); //E8 ?? ?? ?? ?? 83 F8 04 7D ??
                    var offset3 = pe.FindCode(code, offset, offset + 0xFF);
                    if (offset3 == -1)
                    {
                        ShowErrorWindow("Failed in Step 1 - ID check not found.", "Error : " + name);
                        return false;
                    }
                    //pe.ReplaceByte(offset2 + 7, 0); // 04 -> 00
                    //pe.ReplaceByte(offset3 + 7, 0); // 04 -> 00
                    patch = new Patch
                    {
                        Offset = offset2 + 7,
                        Hex = "00"
                    };
                    Patchs.Add(patch);
                    patch = new Patch
                    {
                        Offset = offset3 + 7,
                        Hex = "00"
                    };
                    Patchs.Add(patch);
                    break;
            }
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool DisableWalkDelay(int id, string name)
        {
            string timeGetTimeHex = pe.RawToVa(pe.FindFunctionAddress("winmm.dll", "timeGetTime")).PackToHex(4);
            var code = "FF 15 " + timeGetTimeHex + " " +
                       "8B 8F ?? ?? ?? 00 " +
                       "81 C1 58 02 00 00 " +            //add ecx, 0x258 (600)
                       "3B C1 " +
                       "8B 87 ?? ?? ?? 00 " +
                       "0F 97 C1 " +
                       "8B 40 ?? " +
                       "83 B8 ?? ?? ?? 00 00";
            var offset1 = pe.FindCode(code);
            if (offset1 == -1)
            {
                ShowErrorWindow("Failed in Step 1a - Pattern not found", "Error : " + name);
                return false;
            }

            code = "81 C1 5E 01 00 00 " + //add ecx, 15E (350)
                   "3B C1";
            var offset2 = pe.FindCode(code);
            if (offset2 == -1)
            {
                ShowErrorWindow("Failed in second delay search: Pattern not found", "Error : " + name);
                return false;
            }

            List<Patch> Patchs = new List<Patch>();
            Patch patch;
            if (id == 7) // Change walk delay
            {
                var delay = TwoTextBoxWindow("Number Input", "Input new walk 2 delay(0-1000, default delay1:600, delay:350)", "delay1:", "delay2:", "600", "350");
                if (delay.Item1 == null || delay.Item2 == null || int.TryParse(delay.Item1, out _) != true || int.TryParse(delay.Item2, out _) != true)
                {
                    ShowErrorWindow("Patch Error", "Patch Canceled.");
                    return false;
                }
                byte[] byte1 = BitConverter.GetBytes(Int32.Parse(delay.Item1));
                byte[] byte2 = BitConverter.GetBytes(Int32.Parse(delay.Item2));
                string hex1 = BitConverter.ToString(byte1).Replace("-", " ");
                string hex2 = BitConverter.ToString(byte2).Replace("-", " ");
                patch = new Patch
                {
                    Offset = offset1 + 14,
                    Hex = hex1
                };
                Patchs.Add(patch);

                patch = new Patch
                {
                    Offset = offset2,
                    Hex = "81 C1 " + hex2
                };
                Patchs.Add(patch);
            }
            else // id = 8 Disable walk dely
            {
                patch = new Patch
                {
                    Offset = offset1 + 14,
                    Hex = "00 00 00 00"
                };
                Patchs.Add(patch);

                patch = new Patch
                {
                    Offset = offset2,
                    Hex = "81 C1 00 00 00 00"
                };
                Patchs.Add(patch);
            }
 
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool AllowSpaceInGuildName(int id, string name)
        {
            var code = "6A 20 " +          // push 20
                      "?? " +             // push edx
                      "E8 ?? ?? ?? ?? " + // call <jmp.&_strchr>
                      "83 C4 08 " +       // add esp,8
                      "85 C0";            // test eax,eax
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("Guild Name Pattern Failed in Step 1", "Error : " + name);
                return false;
            }
            offset += code.HexLength();
            //pe.ReplaceByte(offset, 0xEB); // 74 -> EB
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset,
                Hex = "EB"
            };
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool ChangeBossHpBarSize(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0xB00;
            var code = "33 C0 " +
                       "C7 45 FC FF FF FF FF " + //
                       "8B C8 " +
                       "6A 05 " +                //세로
                       "6A 3C " +                //가로
                       "89 ?? ?? 03 00 00 " +
                       "E8";                     // Call Target함수 주소
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                ShowErrorWindow("MVP HP Bar Pattern Not Found.", "Error : " + name);
                return false;
            }

            var calloffset = pe.CallOffset(start, offset + 21); // 후킹함수 주소
            var address = pe.FetchDWord(offset + 22).PackToHex(4); //Target함수 주소
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch
            {
                Offset = offset+22,
                Hex = calloffset
            };
            Patchs.Add(patch);

            var HpBar = TwoTextBoxWindow("Number Input", "Input new width and height for MVP monster HP bar", "Width:", "Height:", "60", "5");
            if (HpBar.Item1 == null || HpBar.Item2 == null || int.TryParse(HpBar.Item1, out _) != true || int.TryParse(HpBar.Item2, out _) != true)
            {
                ShowErrorWindow("Patch Error", "Patch Canceled.");
                return false;
            }
            var width = Int32.Parse(HpBar.Item1).ToString("x");
            var height = Int32.Parse(HpBar.Item2).ToString("x");
            code = "80 BF 04 03 00 00 02 " + //
                   "75 10 " +
                   "C7 44 24 04 " + width + " 00 00 00 " +  // 가로 3C 
                   "C7 44 24 08 " + height + " 00 00 00 " + // 세로 0F 
                   "EB 04 " +
                   "00 00 00 00 " +
                   "51 " +
                   "E8 00 00 00 00 " +
                   "59 " +
                   "83 C1 17 " +
                   "FF 74 24 0C " +
                   "FF 74 24 0C " +
                   "51 " +
                   "8B 4C 24 0C " +
                   "68 " + address + " " + // 원래 호출 함수
                   "C3 " +
                   "59 " +
                   "EB 02 " +
                   "00 00 " +
                   "C2 08 00";
            patch = new Patch
            {
                Offset = start,
                Hex = code
            };

            //pe.ReplaceHex(start, code);
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool IncreaseZoomOut(int id, string name)
        {
            int start = (int)pe.SectionHeaders[1].PointerToRawData;
            int end = start + (int)pe.SectionHeaders[1].SizeOfRawData;
            var code = "00 00 F0 43 00 00";
            var offset = pe.FindCode(code,start,end);
            if (offset == -1)
            {
                ShowErrorWindow("Increase Zoom Out Pattern Not Found.", "Error : " + name);
                return false;
            }
            List<Patch> Patchs = new List<Patch>();
            Patch patch = new Patch();
            
            switch (id)
            {
                case 25: // 25%
                    patch = new Patch
                    {
                        Offset = offset,
                        Hex = "00 00 80 43"
                    };
                    break;
                case 26: // 50%
                    patch = new Patch
                    {
                        Offset = offset,
                        Hex = "00 00 FF 43"
                    };
                    break;
                case 27: // 75%
                    patch = new Patch
                    {
                        Offset = offset,
                        Hex = "00 00 4C 44"
                    };
                    break;
                case 28: // Max
                    patch = new Patch
                    {
                        Offset = offset,
                        Hex = "00 00 99 44"
                    };
                    break;
                case 29:
                    var angle = OneTextBoxWindow("Number Input", "Input Zoom level(256-1224, deault:480, 25%:256, 50%:510, 75%:816, Max:1224)", "480");
                    if (angle == null || Int32.Parse(angle) < 256 || Int32.Parse(angle) > 1224 || !int.TryParse(angle, out _))
                    {
                        ShowErrorWindow("Patch Error", "Patch Canceled.");
                        return false;
                    }
                    byte[] bytes = BitConverter.GetBytes(Int32.Parse(angle));
                    string result = BitConverter.ToString(bytes).Replace("-", " ");
                    patch = new Patch
                    {
                        Offset = offset,
                        Hex = result
                    };
                    break;
            }
            Patchs.Add(patch);
            Items[id].PatchList = Patchs;
            return true;
        }

        private bool SkipLicenseScreen(int id, string name)
        {
            var offset = pe.StringVa("btn_disagree");
            if (offset == -1)
            {
                ShowErrorWindow("Failed in Step 1 - Unable to find btn_disagree", "Error : " + name);
                return false;
            }
            var offset1 = pe.FindCode("68 " + offset.PackToHex(4));
            if (offset1 == -1)
            {
                ShowErrorWindow("Failed in Step 1 - Unable to find reference to btn_disagree", "Error : " + name);
                return false;
            }
            var code = "FF 24 85 ?? ?? ?? 00";
            offset = pe.FindCode(code, offset1 - 0x200, offset1);
            var switchOffet = 3;
            if (offset == -1)
            {
                offset = pe.FindCode(code,offset1 - 0x250,offset1);
                switchOffet = 3;
            }
            if (offset == -1)
            {
                offset = pe.FindCode(code, offset1 - 0x300, offset1);
                switchOffet = 3;
            }
            if (offset == -1)
            {
                ShowErrorWindow("Failed in Step 2 - Unable to find the switch", "Error : " + name);
                return false;
            }
            var refaddr = pe.VaToRaw(pe.FetchDWord(offset + switchOffet));
            var third = pe.FetchDWord(refaddr).PackToHex(4);

            List<Patch> Patchs = new List<Patch>()
            {
                new Patch
                {
                    Offset = refaddr,
                     Hex = third
                },
                new Patch
                {
                    Offset = refaddr + 4,
                    Hex = third
                }
            };
            
            Items[id].PatchList = Patchs;

            return true;
        }

        private bool CustomWindowTitle(int id, string name)
        {
            var oldTitle = "Ragnarok";
            var titleOffset = pe.StringVa(oldTitle);
            if (titleOffset == -1)
            {
                ShowErrorWindow("Old title not found", "Error : " + name);
                return false;
            }
            var title = OneTextBoxWindow("Input String", "Input the new title", "Ragnarok");
            if (title == null || title == "Ragnarok" || title.Length > 200)
            {
                ShowErrorWindow("Patch Error", "Patch Canceled.");
                return false;
            }
            Encoding eucKr = Encoding.GetEncoding("euc-kr");
            byte[] array = eucKr.GetBytes(title.Trim());

            // array.Length 문자열 크기 체크(200자 이하)
            string hex = BitConverter.ToString(array).Replace("-", " ");

            var code = "C7 05 ?? ?? ?? 00 " + titleOffset.PackToHex(4);
            var offset = pe.FindCode(code);
            if (offset == -1)
            {
                code = "C7 05 ?? ?? ?? 01 " + titleOffset.PackToHex(4);
                offset = pe.FindCode(code);
            }
            if (offset == -1)
            {
                ShowErrorWindow("Failed in Step 2", "Error : " + name);
                return false;
            }
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0x660;

            List<Patch> Patchs = new List<Patch>()
            {
                new Patch  // New Title 저장 
                {
                    Offset = start,
                    Hex = hex + " 00"
                },
                new Patch
                {
                    Offset = offset + code.HexLength() - 4,
                    Hex = pe.RawToVa(start).PackToHex(4)
                }
            };

            Items[id].PatchList = Patchs;

            return true;
        }

        private bool SetHardcodedServerip(int id, string name)
        {
            int start = (int)pe.SectionHeaders[pe.NtHeader.FileHeader.NumberOfSections - 1].PointerToRawData + 0xc00;
            string inetAddr = pe.RawToVa(pe.FindFunctionAddress("ws2_32.dll", "inet_addr")).PackToHex(4);
            var offsets = pe.FindCodes("FF 15 " + inetAddr);
            if (offsets.Count == 0)
            {
                ShowErrorWindow("Not Found Inet_Addr", "Error : " + name);
                return false;
            }

            List<Patch> Patchs = new List<Patch>();
            foreach(var offset in offsets)
            {
                Patch patch = new Patch()
                {
                    Offset = offset + 2,
                    Hex = pe.RawToVa(start + 0xd9).PackToHex(4)
                };
                Patchs.Add(patch);
            }
            string ip = OneTextBoxWindow("Input string", "Input Server IP", "127.0.0.1");
            if(ip == null)
            {
                ShowErrorWindow("Patch Error", "Patch Canceled.");
                return false;
            }
            byte[] ipBytes;
            try
            {
                ipBytes = IPAddress.Parse(ip).GetAddressBytes();
            }
            catch(Exception ex)
            {
                ShowErrorWindow("IP Error", "Only IPv4 addresses are supported.");
                Console.WriteLine(ex.Message);
                return false;
            }
            
            //if (ipBytes.Length !=4)
            //{
            //    ShowErrorWindow("IP Error", "Only IPv4 addresses are supported.");
            //    return false;
            //}
            byte[] xorKey = { 0x80, 0xBD, 0x9B, 0x48 };
            byte[] resultBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                resultBytes[i] = (byte)(ipBytes[i] ^ xorKey[i]);
            }
            resultBytes[0] = (byte)(resultBytes[0] + 0x03);
            resultBytes[1] = (byte)(resultBytes[1] + 0x12);
            string ipstring = string.Format("{0:X2} {1:X2} {2:X2} {3:X2}",resultBytes[0], resultBytes[1], resultBytes[2], resultBytes[3]);
            var code = "57 " +
                       "56 " +
                       "83 EC 0C " +
                       "8B 4C 24 18 " +
                       "A1 " + pe.RawToVa(start + 0xbd).PackToHex(4) + " " +
                       "8B 35 " + pe.RawToVa(start + 0xc5).PackToHex(4) + " " +
                       "BA 01 47 93 62 " +
                       "89 14 24 " +
                       "C7 44 24 04 02 19 31 05 " +
                       "89 54 24 08 " +
                       "80 39 0A " +
                       "74 06 " +
                       "80 79 01 0D " +
                       "75 19 " +
                       "0F BE 51 02 " +
                       "0F AF 51 04 " +
                       "03 15 " + pe.RawToVa(start + 0xb5).PackToHex(4) + " " +
                       "01 14 24 " +
                       "8B 0D " + pe.RawToVa(start + 0xb9).PackToHex(4) + " " +
                       "EB 10 " +
                       "8B 0D " + pe.RawToVa(start + 0xb9).PackToHex(4) + " " +
                       "41 " +
                       "89 0D " + pe.RawToVa(start + 0xb9).PackToHex(4) + " " +
                       "FF 0C 24 " +
                       "33 44 24 04 " +
                       "31 04 24 " +
                       "8B 04 24 " +
                       "83 E0 03 " +
                       "83 F8 01 " +
                       "83 D9 FF " +
                       "68 03 00 00 00 " +
                       "5F " +
                       "8B C1 " +
                       "33 D2 " +
                       "F7 F7 " +
                       "85 D2 " +
                       "74 04 " +
                       "FF 04 24 " +
                       "49 " +
                       "A1 " + pe.RawToVa(start + 0xb5).PackToHex(4) + " " +
                       "6B D0 0A " +
                       "01 14 24 " +
                       "81 C6 FD ED FF FF " +
                       "33 74 24 04 " +
                       "6B C0 F6 " +
                       "03 04 24 " +
                       "33 C6 " +
                       "33 44 24 08 " +
                       "83 C1 02 " +
                       "89 0D " + pe.RawToVa(start + 0xb9).PackToHex(4) + " " +
                       "83 C4 0C " +
                       "5E " +
                       "5F " +
                       "C2 04 00 " +
                       "41 44 03 00 " +
                       "00 00 00 00 " +
                       "80 BD 9B 48 " +  // 복호화 코드
                       "51 65 3D 1D " +
                       ipstring + " " +  // 암호화 IP 주소
                       "EB 04 " +
                       "00 00 00 00 " +
                       "FF 25 " + inetAddr + " " +
                       "00 00 00 00 " +
                       pe.RawToVa(start).PackToHex(4);
            Patch patch2 = new Patch()
            {
                Offset = start,
                Hex = code
            };
            Patchs.Add(patch2);
            Items[id].PatchList = Patchs;

            return true;
        }

        private bool DisableHelpMsg(int id, string name)
        {
            var code = "75 ?? 8B 0D ?? ?? ?? ?? 6A 00 6A 00 6A 00 8B 01 6A 0E 6A 2A FF 50 18";
            var offset = pe.FindCode(code);
            if (offset == -1 )
            {
                ShowErrorWindow("Not Found Pattern", "Error : " + name);
                return false;
            }

            List<Patch> Patchs = new List<Patch>()
            {
                new Patch()
                {
                    Offset = offset,
                    Hex = "EB"
                }
            };

            Items[id].PatchList = Patchs;

            return true;
        }
        #endregion

        #region Method
        private string GetFilePath()
        {
            OpenFileDialog od = new OpenFileDialog
            {
                Title = "Select a file", // 대화창의 제목 설정
                Filter = "Exe file (*.exe)|*.exe" // 파일 형식 필터
            };


            // 대화창을 표시하고 결과를 확인
            if (od.ShowDialog() == true)
            {
                return od.FileName; // 사용자가 선택한 파일의 전체 경로명 반환
            }

            return null; // 사용자가 취소하거나 파일을 선택하지 않은 경우
        }

        private string GetLogFilePath()
        {
            OpenFileDialog od = new OpenFileDialog
            {
                Title = "Select a file", // 대화창의 제목 설정
                Filter = "Log file (*.log)|*.log" // 파일 형식 필터
            };


            // 대화창을 표시하고 결과를 확인
            if (od.ShowDialog() == true)
            {
                return od.FileName; // 사용자가 선택한 파일의 전체 경로명 반환
            }

            return null; // 사용자가 취소하거나 파일을 선택하지 않은 경우
        }

        private void LoadFile(string filename)
        {
            pe = new PEReader(filename);
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            uint timeDateStamp = pe.NtHeader.FileHeader.TimeDateStamp;
            DateTime? buildDate = epoch.AddSeconds(timeDateStamp).ToLocalTime();
            TxbClient.Text = buildDate.ToString();
        }

        public void ReadItems()
        {
            Items = new ObservableCollection<Item>
            {
                new Item { Id = 0, Recommend = true, Group = 0, IsToggled = 0, Name = "@ Bug Fix(Recommended)", OnToggle = () => FixChatAtBugFix(0,"@ Bug Fix") },
                new Item { Id = 1, Recommend = false, Group = 0, IsToggled = 0, Name = "Add Close Button", OnToggle = () => AddCloseButton(1,"Add Close Button") },
                new Item { Id = 2, Recommend = false, Group = 0, IsToggled = 0, Name = "Allow Space In Guild Name", OnToggle = () => AllowSpaceInGuildName(2,"Allow Space In Guild Name") },
                new Item { Id = 3, Recommend = false, Group = 1, IsToggled = 0, Name = "Chat Flood Allow", OnToggle = () => ChatFloodRemoveLimit(3,"Chat Flood Allow") },
                new Item { Id = 4, Recommend = false, Group = 1, IsToggled = 0, Name = "Chat Flood Remove Limit", OnToggle = () => ChatFloodRemoveLimit(4,"Chat Flood Remove Limit") },
                new Item { Id = 5, Recommend = false, Group = 0, IsToggled = 0, Name = "Custom Window Title", OnToggle = () => CustomWindowTitle(5, "Custom Window Title") }, // 0x660
                 new Item { Id = 6, Recommend = false, Group = 0, IsToggled = 0, Name = "Change MVP Hp Bar Size", OnToggle = () => ChangeBossHpBarSize(6, "Change MVP Hp Bar Size") }, //0xB00
                new Item { Id = 7, Recommend = false, Group = 4, IsToggled = 0, Name = "Change Walk Delay", OnToggle = () => DisableWalkDelay(7,"Change Walk Delay") },
                new Item { Id = 8, Recommend = false, Group = 4, IsToggled = 0, Name = "Disable Walk Delay", OnToggle = () => DisableWalkDelay(8,"Disable Walk Delay") },
                new Item { Id = 9, Recommend = true, Group = 0, IsToggled = 0, Name = "Disable 1rag1 Params(Recommended)", OnToggle = () => Disable1rag1Params(9,"Disable 1rag1 Params") },
                new Item { Id = 10, Recommend = false, Group = 0, IsToggled = 0, Name = "Disable 4Letter Character Limit", OnToggle = () => Disable4LetterLimit(10,"Disable 4Letter Character Limit") },
                new Item { Id = 11, Recommend = false, Group = 0, IsToggled = 0, Name = "Disable 4Letter Password Limit", OnToggle = () => Disable4LetterLimit(11,"Disable 4Letter Password Limit") },
                new Item { Id = 12, Recommend = false, Group = 0, IsToggled = 0, Name = "Disable 4Letter UserName Limit", OnToggle = () => Disable4LetterLimit(12,"Disable 4Letter UserName Limit") },
                new Item { Id = 13, Recommend = true, Group = 0, IsToggled = 0, Name = "Disalbe Filename Check(Recommended)", OnToggle = () => DisableFilenameCHeck(13,"Disalbe Filename Check") },
                new Item { Id = 14, Recommend = false, Group = 0, IsToggled = 0, Name = "Disable Indoor RSW", OnToggle = () => DisableIndoorRSW(14,"Disable Indoor RSW") },
                new Item { Id = 15, Recommend = false, Group = 0, IsToggled = 0, Name = "Disalbe Swear Filter", OnToggle = () => DisableSwearFilter(15,"Disalbe Swear Filter") },
                new Item { Id = 16, Recommend = false, Group = 0, IsToggled = 0, Name = "Enable 44khz Audio", OnToggle = () => Enable44khzAudio(16,"Enable 44khz Audio") },
                new Item { Id = 17, Recommend = false, Group = 0, IsToggled = 0, Name = "Enable DNS Suport", OnToggle = () => EnableDNSSuport(17,"Enable DNS Suport") }, // 0x800
                new Item { Id = 18, Recommend = true, Group = 0, IsToggled = 0, Name = "Enable Multiple GRF(Recommended)", OnToggle = () => EnableMultipleGRF(18,"Enable Multiple GRF") }, //0x700
                new Item { Id = 19, Recommend = false, Group = 2, IsToggled = 0, Name = "Fix Camera Angles(Custom)", OnToggle = () => FixCameraAngles(19,"Fix Camera Angles(Custom") },
                new Item { Id = 20, Recommend = false, Group = 2, IsToggled = 0, Name = "Fix Camera Angles(Full)", OnToggle = () => FixCameraAngles(20,"Fix Camera Angles(Full") },
                new Item { Id = 21, Recommend = false, Group = 2, IsToggled = 0, Name = "Fix Camera Angles(Less)", OnToggle = () => FixCameraAngles(21,"Fix Camera Angles(Less)") },
                new Item { Id = 22, Recommend = false, Group = 2, IsToggled = 0, Name = "Fix Camera Angles(Recommended)", OnToggle = () => FixCameraAngles(22,"Fix Camera Angles(Recommended)") },
                new Item { Id = 23, Recommend = false, Group = 0, IsToggled = 0, Name = "Fix NPC Dialog Scroll", OnToggle = () => FixNpcDialogScroll(23,"Fix NPC Dialog Scroll") },
                new Item { Id = 24, Recommend = false, Group = 0, IsToggled = 0, Name = "Increase Map Quality", OnToggle = () => IncreaseMapQuality(24,"Increase Map Quality") },
                new Item { Id = 25, Recommend = false, Group = 3, IsToggled = 0, Name = "Increase Zoom Out 25%", OnToggle = () => IncreaseZoomOut(25, "Increase Zoom Out 25%") },
                new Item { Id = 26, Recommend = false, Group = 3, IsToggled = 0, Name = "Increase Zoom Out 50%", OnToggle = () => IncreaseZoomOut(26, "Increase Zoom Out 50%") },
                new Item { Id = 27, Recommend = false, Group = 3, IsToggled = 0, Name = "Increase Zoom Out 75%", OnToggle = () => IncreaseZoomOut(27, "Increase Zoom Out 75%") },
                new Item { Id = 28, Recommend = false, Group = 3, IsToggled = 0, Name = "Increase Zoom Out Max", OnToggle = () => IncreaseZoomOut(28, "Increase Zoom Out Max") },
                new Item { Id = 29, Recommend = false, Group = 3, IsToggled = 0, Name = "Increase Zoom Out Custom", OnToggle = () => IncreaseZoomOut(29, "Increase Zoom Out Custom") },
                new Item { Id = 30, Recommend = true, Group = 0, IsToggled = 0, Name = "Read Data Folder First(Recommended)", OnToggle = () => ReadDataFolderFirst(30,"Read Data Folder First") },
                new Item { Id = 31, Recommend = true, Group = 0, IsToggled = 0, Name = "Restore Clientinfo.xml & No Hard Coded Address & Port(Recommended)", OnToggle = () => RestoreClientinfoxmlNoHardCodedAddress(31,"Restore Clientinfo.xml & No Hard Coded Address & Port") }, //0x100
                new Item { Id = 32, Recommend = true, Group = 0, IsToggled = 0, Name = "Restore Old Login Packet(Recommended)", OnToggle = () => RestoreOldLoginPacket(32,"Restore Old Login Packet") },
                new Item { Id = 33, Recommend = false, Group = 0, IsToggled = 0, Name = "Restore Roulette", OnToggle = () => RestoreRoulette(33,"Restore Roulette") }, // 0x900
                new Item { Id = 34, Recommend = true, Group = 0, IsToggled = 0, Name = "Remove OTP Login(Recommended)", OnToggle = () => RemoveOTPLogin(34,"Restore Old Login Packet") },
                new Item { Id = 35, Recommend = false, Group = 0, IsToggled = 0, Name = "Show Replay Button", OnToggle = () => ShowReplayButton(35,"Show Replay Button") }, // 0xA00
                new Item { Id = 36, Recommend = false, Group = 0, IsToggled = 0, Name = "Skip License Screen", OnToggle = () => SkipLicenseScreen(36, "Skip License Screen") },
                new Item { Id = 37, Recommend = false, Group = 0, IsToggled = 0, Name = "Set Hardcoded Server ip", OnToggle = () => SetHardcodedServerip(37, "Set Hardcoded Server ip") },
                new Item { Id = 38, Recommend = true, Group = 0, IsToggled = 0, Name = "Disable Help Message", OnToggle = () => DisableHelpMsg(38,"Disable Help Message") }
            };

            //var sortedItems = Items.OrderBy(item => item.Name).ToList();  //정렬상태로 보여 줄때 Items 대신 sortedItmes를 사용
            filteredItems = new ObservableCollection<Item>(Items);
            DgdItem.ItemsSource = filteredItems;

            PatchCount = 0;
            TxbPatches.Text = "0";
        }

        private void ShowErrorWindow(string title, string message)
        {
            var parentWindow = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
            var errorWindow = new ErrorWindow(title, message)
            {
                Owner = parentWindow
            };
            errorWindow.ShowDialog();
        }

        private void InformWindow(string message)
        {
            var parentWindow = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
            var informWindow = new InformWindow(message)
            {
                Owner = parentWindow
            };
            informWindow.ShowDialog();
        }

        private string OneTextBoxWindow(string title, string message, string val)
        {
            var parentWindow = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
            var oneTextBox = new OneTextBox(title, message, val)
            {
                Owner = parentWindow
            };
            if (oneTextBox.ShowDialog() == true)
            {
                return oneTextBox.Result;
            }
            else
            {
                return null;
            }
        }

        private (string, string) TwoTextBoxWindow(string title, string message, string target1, string target2, string val1, string val2)
        {
            var parentWindow = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
            var twoTextBox = new TwoTextBox(title, message, target1, target2, val1, val2)
            {
                Owner = parentWindow
            };
            if (twoTextBox.ShowDialog() == true)
            {
                return (twoTextBox.Result1, twoTextBox.Result2);
            }
            else
            {
                return (null, null);
            }
        }
        #endregion

        #region event handler
        private async void URPO_Loaded(object sender, RoutedEventArgs e)
        {
            await Task.Delay(100);
            PopupWindow popup = new PopupWindow
            {
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner // 부모 창 기준으로 중앙에 띄움
            };
            popup.ShowDialog(); // 모달 팝업 창 실행
        }

        private void BtnSelect_Click(object sender, RoutedEventArgs e)
        {
            FilePath = GetFilePath();
            if (FilePath != null)
            {
                TxtClientFile.Text = FilePath;
                LoadFile(FilePath);
                ReadItems();
                BtnApply.IsEnabled = true;
                BtnRecommended.IsEnabled = true;
                BtnLoadProfile.IsEnabled = true;
                BtnSaveProfile.IsEnabled = true;
            }
        }

        private void CloseWindowButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void MinWindowButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            TxtFilter.Text = string.Empty;
        }

        private void TxtFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            var searchText = TxtFilter.Text.ToLower();
            var filtered = Items.Where(item => item.Name.ToLower().Contains(searchText));
            filteredItems.Clear();
            foreach (var item in filtered)
            {
                filteredItems.Add(item);
            }
        }

        private void BtnApply_Click(object sender, RoutedEventArgs e)
        {
            if (PatchCount != 0 )
            {
                foreach (var item in Items.Where(i => i.PatchList != null))
                {
                    foreach (var patch in item.PatchList)
                    {
                        int offset = patch.Offset;
                        string code = patch.Hex;
                        pe.ReplaceHex(offset, code);
                    }
                }
                string directory = Path.GetDirectoryName(FilePath);
                string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(FilePath);
                string newFileName = $"{fileNameWithoutExtension}_patched.exe";
                try
                {
                    pe.SaveFile(Path.Combine(directory, newFileName));
                    InformWindow("The patch has been completed.");
                }
                catch (Exception ex) 
                {
                    MessageBox.Show($"An error occurred while saving the file..\n\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                InformWindow("There are no applied patches.");
            }
        }

        private void BtnRecommended_Click(object sender, RoutedEventArgs e)
        {
            var filteredItems = Items.Where(i => i.Recommend == true);
            DgdItem.SelectedItems.Clear();
            foreach(var item in filteredItems)
            {
                DgdItem.SelectedItems.Add(item);
            }
            InformWindow("The recommended patch selection is complete.");
        }

        private void BtnLoadProfile_Click(object sender, RoutedEventArgs e)
        {
            DgdItem.SelectedItems.Clear();
            var path = GetLogFilePath();
            if (path != null)
            {
                
                string[] lines = File.ReadAllLines(path);
                for  (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i];
                    string[] parts = line.Split(',');
                    if (parts.Length >= 1)
                    {
                        int targetid = int.Parse(parts[0].Trim());
                        var targetItem = Items.FirstOrDefault(item=>item.Id == targetid);
                        if (targetItem != null)
                        {
                            DgdItem.SelectedItem = targetItem;
                        }

                    }
                }
                InformWindow("The profile has been loaded.");
            }
            else
            {
                InformWindow("It has been canceled");
            }
            
        }

        private void BtnSaveProfile_Click(object sender, RoutedEventArgs e)
        {
            var logitems = Items.Where(item => item.IsToggled == 1);
            string directory = Path.GetDirectoryName(FilePath);
            string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(FilePath);
            string newFileName = $"{fileNameWithoutExtension}_patched.exe.log";
            using (StreamWriter sw = new StreamWriter(Path.Combine(directory, newFileName)))
            {
                sw.WriteLine("Id, IsToggled, Name");
                foreach(var item in logitems)
                {
                    sw.WriteLine($"{item.Id}, {item.IsToggled}, {item.Name}");
                }
            }
            InformWindow("Profile writing is complete.");
        }

        private void DgdItem_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DgdItem.SelectedItem is Item item)
            {
                if (item.IsToggled != 0)
                {
                    PatchCount--;
                    TxbPatches.Text = PatchCount.ToString();
                    item.PatchList = null;
                    item.IsToggled = 0;
                }
                else
                {
                    bool isSuccess = item.OnToggle?.Invoke() ?? false;
                    if (isSuccess) //패치 성공시 
                    {
                        if (item.Group == 0)
                        {
                            PatchCount++;
                            TxbPatches.Text = PatchCount.ToString();
                            item.IsToggled = 1;
                        }
                        else
                        {
                            switch (item.Group)
                            {
                                case 1: // Chat Flood
                                    if (Items[3].IsToggled == 1 || Items[4].IsToggled == 1)
                                    {
                                       if (item.Id ==3)
                                       {
                                            Items[4].IsToggled = 0;
                                            item.IsToggled = 1;
                                        }
                                       else
                                       {
                                            Items[3].IsToggled = 0;
                                            item.IsToggled = 1;
                                        }
                                    }
                                    else
                                    {
                                        PatchCount++;
                                        TxbPatches.Text = PatchCount.ToString();
                                        item.IsToggled = 1;
                                    }
                                    break;
                                case 2: // Camera Angles
                                    if (Items[19].IsToggled == 1 || Items[20].IsToggled == 1 || Items[21].IsToggled == 1 || Items[22].IsToggled == 1)
                                    {
                                        int check;
                                        switch (item.Id)
                                        {
                                            case 19:
                                                if (Items[20].IsToggled == 1) check = 20;
                                                else if (Items[21].IsToggled == 1) check = 21;
                                                else check = 22;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 20:
                                                if (Items[19].IsToggled == 1) check = 19;
                                                else if (Items[21].IsToggled == 1) check = 21;
                                                else check = 22;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 21:
                                                if (Items[19].IsToggled == 1) check = 19;
                                                else if (Items[20].IsToggled == 1) check = 20;
                                                else check = 22;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 22:
                                                if (Items[19].IsToggled == 1) check = 19;
                                                else if (Items[20].IsToggled == 1) check = 20;
                                                else check = 21;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        PatchCount++;
                                        TxbPatches.Text = PatchCount.ToString();
                                        item.IsToggled = 1;
                                    }
                                    break;
                                case 3: // Zoom
                                    if (Items[25].IsToggled == 1 || Items[26].IsToggled == 1 || Items[27].IsToggled == 1 || Items[28].IsToggled == 1
                                        || Items[29].IsToggled == 1)
                                    {
                                        int check;
                                        switch (item.Id)
                                        {
                                            case 25:
                                                if (Items[26].IsToggled == 1) check = 26;
                                                else if (Items[27].IsToggled == 1) check = 27;
                                                else if (Items[28].IsToggled == 1) check = 28;
                                                else check = 29;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 26:
                                                if (Items[25].IsToggled == 1) check = 25;
                                                else if (Items[27].IsToggled == 1) check = 27;
                                                else if (Items[28].IsToggled == 1) check = 28;
                                                else check = 29;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 27:
                                                if (Items[25].IsToggled == 1) check = 25;
                                                else if (Items[26].IsToggled == 1) check = 26;
                                                else if (Items[28].IsToggled == 1) check = 28;
                                                else check = 29;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 28:
                                                if (Items[25].IsToggled == 1) check = 25;
                                                else if (Items[26].IsToggled == 1) check = 26;
                                                else if (Items[27].IsToggled == 1) check = 27;
                                                else check = 29;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                            case 29:
                                                if (Items[25].IsToggled == 1) check = 25;
                                                else if (Items[26].IsToggled == 1) check = 26;
                                                else if (Items[27].IsToggled == 1) check = 27;
                                                else check = 28;
                                                Items[check].IsToggled = 0;
                                                item.IsToggled = 1;
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        PatchCount++;
                                        TxbPatches.Text = PatchCount.ToString();
                                        item.IsToggled = 1;
                                    }
                                    break;
                                case 4: // Walk Delay
                                    if (Items[7].IsToggled == 1 || Items[8].IsToggled == 1)
                                    {
                                        if (item.Id == 7)
                                        {
                                            Items[8].IsToggled = 0;
                                            item.IsToggled = 1;
                                        }
                                        else
                                        {
                                            Items[7].IsToggled = 0;
                                            item.IsToggled = 1;
                                        }
                                    }
                                    else
                                    {
                                        PatchCount++;
                                        TxbPatches.Text = PatchCount.ToString();
                                        item.IsToggled = 1;
                                    }
                                    break;
                            }
                        }
                        
                    }
                }
                DgdItem.SelectedItem = null; // 선택 해제로 같은 행 재 선택가능하게 초기화
            }
        }
        #endregion
    }
}
