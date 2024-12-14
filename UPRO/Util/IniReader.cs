using System.Collections.Generic;
using System.IO;

namespace UPRO.Util
{
    public class IniReader
    {
        private string filePath;
        private Dictionary<string, Dictionary<string, string>> iniData = new Dictionary<string, Dictionary<string, string>>();

        public IniReader(string filePath)
        {
            this.filePath = filePath;
            ReadIniFile(filePath);
        }

        private void ReadIniFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("The specified ini file was not found.", filePath);
            }

            var currentSection = new Dictionary<string, string>();
            string currentSectionName = "";

            foreach (var line in File.ReadAllLines(filePath))
            {
                string trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine)) continue; // 비어 있는 라인은 확인

                if (trimmedLine.StartsWith("[") && trimmedLine.EndsWith("]")) // New section
                {
                    if (!string.IsNullOrEmpty(currentSectionName))
                    {
                        iniData[currentSectionName] = currentSection;
                    }

                    currentSectionName = trimmedLine.Substring(1, trimmedLine.Length - 2);
                    currentSection = new Dictionary<string, string>();
                }
                else
                {
                    var keyValue = trimmedLine.Split(new char[] { '=' }, 2);
                    if (keyValue.Length != 2)
                        continue; // Invalid line

                    currentSection[keyValue[0].Trim()] = keyValue[1].Trim();
                }
            }

            if (!string.IsNullOrEmpty(currentSectionName))
            {
                iniData[currentSectionName] = currentSection;
            }
        }

        public void SetValue(string section, string key, string value)
        {
            if (!iniData.ContainsKey(section))
            {
                iniData[section] = new Dictionary<string, string>();
            }

            iniData[section][key] = value;
            WriteIniFile();
        }

        private void WriteIniFile()
        {
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                foreach (var section in iniData)
                {
                    writer.WriteLine($"[{section.Key}]");
                    foreach (var keyValuePair in section.Value)
                    {
                        writer.WriteLine($"{keyValuePair.Key} = {keyValuePair.Value}");
                    }
                    writer.WriteLine();
                }
            }
        }

        public string GetValue(string section, string key)
        {
            if (iniData.ContainsKey(section))
            {
                if (iniData[section].ContainsKey(key))
                {
                    return iniData[section][key];
                }
                else
                {
                    throw new KeyNotFoundException($"The key '{key}' was not found in section '{section}'.");
                }
            }
            else
            {
                throw new KeyNotFoundException($"The section '{section}' was not found.");
            }
        }

    }
}
