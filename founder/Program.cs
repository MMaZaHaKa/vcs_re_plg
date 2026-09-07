using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace FunctionInfoTool
{
    public class FunctionInfo
    {
        public string Name                  { get; set; }
        public string IdaStringAddress      { get; set; }
        public uint IdaAddress              { get; set; }
        public uint ElfAddress              { get; set; }
        public int CodeLinesCommentStart    { get; set; }
        public int CodeLinesStart           { get; set; }
        public string FuncHeader            { get; set; }
        public List<string> CodeLines       { get; set; } = new List<string>();
        public List<string> FuncsInto       { get; set; } = new List<string>();
        public List<int> FuncsIntoIndicies  { get; set; } = new List<int>();
        public byte[] Bytes                 { get; set; }
        public uint Size                    { get; set; }
        public string Md5Hash               { get; set; }
        public bool IsRenamed               { get; set; }
        public bool IsLowRenamed            { get; set; }
        public bool IsFunctionEmpty         { get; set; }
    }

    public class Parser
    {
        private readonly string _cFilePath;
        private readonly string _elfPath;
        private readonly uint _elfHeaderSize;
        private readonly uint _idaBase;
        private readonly bool _skipElf;

        //private static readonly Regex CommentRegex = new Regex("^\\s*//-+\\s*\\(([0-9A-Fa-f]+)\\)"); // new
        private static readonly Regex CommentRegex = new Regex(@"^\s*//-+\s*\(([0-9A-Fa-f]+)\)"); // old
        //private static readonly Regex HeaderRegex = new Regex(@"\w+\s+(?:__\w+\s+)?(?<name>\w+)\s*\(.*");
        //private static readonly Regex AutoNameRegex = new Regex("^(sub_[0-9A-Fa-f]+|nullsub_.*)$");

        static public bool IsFunctionEmpty(List<string> code, bool with_header) {
            List<string> ccode = code;
            if (with_header && ccode.Count > 0) { ccode.RemoveAt(0); }
            return string.Join("", ccode).Replace(" ", "").Replace("\t", "").Replace("\r", "")
                .Replace("\n", "").Replace("{", "").Replace("}", "").Replace(";", "").Trim() == "";
        }


        static public string RemoveComment(string code_row)
        {
            int commentPos = code_row.IndexOf("//", StringComparison.Ordinal);
            return commentPos >= 0
                ? code_row.Substring(0, commentPos).TrimEnd()
                : code_row;
        }

        static public List<string> SparseFuncsNames(string code_row)
        {
            if (string.IsNullOrEmpty(code_row))
                return new List<string>();

            // Список имён, которые нужно пропускать
            var skipList = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "sizeof",
                "HIWORD",
                "LOWORD",
                "SLOWORD",
            };

            // Регулярка для поиска идентификатора перед открывающейся скобкой
            var regex = new Regex(@"\b([A-Za-z_]\w*)\s*\(", RegexOptions.Compiled);
            var matches = regex.Matches(code_row);

            // Используем HashSet для автоматического исключения дубликатов
            var uniqueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in matches)
            {
                var name = m.Groups[1].Value;
                if (!skipList.Contains(name))
                    uniqueNames.Add(name);
            }

            return uniqueNames.ToList();
        }


        public Parser(string elfPath, string cFilePath, uint elfHeaderSize, uint idaBase, bool skipElf = false)
        {
            _elfPath = elfPath;
            _cFilePath = cFilePath;
            _elfHeaderSize = elfHeaderSize;
            _idaBase = idaBase;
            _skipElf = skipElf;

            if (!skipElf && !File.Exists(_elfPath)) { Console.WriteLine("ELF file not found"); return; }
            if (!File.Exists(cFilePath)) { Console.WriteLine("C file not found"); return; }
        }

        public List<FunctionInfo> Parse(bool fast = true)
        {
            string[] c_lines = File.ReadAllLines(_cFilePath);
            byte[] binaryData = _skipElf ? Array.Empty<byte>() : File.ReadAllBytes(_elfPath);

            List<FunctionInfo> functions = new List<FunctionInfo>();

            // Find functions (parse funcs pointers, names, renamed testing, calc elf offset, sort)
            for (int i = 0; i < c_lines.Length; i++)
            {
                var m = CommentRegex.Match(c_lines[i]);
                if (!m.Success) { continue; }

                string hexAddr = m.Groups[1].Value.Trim(); // "00102D38"
                if (!uint.TryParse(hexAddr, System.Globalization.NumberStyles.HexNumber, null, out uint addr)) { continue; }
                string trimedHexAddr = $"{addr:X}"; // "102D38"
                //string trimmedHexAddr = addr.ToString("X");

                // find next non-empty, non-comment line
                int j = i + 1;
                while (j < c_lines.Length && (string.IsNullOrWhiteSpace(c_lines[j]) || c_lines[j].TrimStart().StartsWith("//"))) j++;
                if (j >= c_lines.Length) { break; }
                string line = c_lines[j].Trim();
                if (line.StartsWith("#error ")) { continue; }

                //var mh = HeaderRegex.Match(c_lines[j]);
                //if (!mh.Success) { continue; } // not parse "__int64 __fastcall CRunningScript::ProcessCommand_60_(CRunningScript *this)"
                //string name = mh.Groups["name"].Value.Trim();

                string name = "";

                // todo int (*__fastcall sub_21B3FC(int (*result)(void)))(void)   :/
                // Находим первую '('
                int posOpenParen = line.IndexOf('(');
                int posCloseParen = line.IndexOf(')', posOpenParen);
                int openParenCount = line.Count(c => c == '(');
                int closeParenCount = line.Count(c => c == ')');
                if (posOpenParen != -1)
                {
                    // Ищем последний пробел перед '('
                    int posSpace = line.LastIndexOf(' ', posOpenParen);

                    name = (posSpace != -1)
                        ? line.Substring(posSpace + 1, posOpenParen - posSpace - 1)
                        : line.Substring(0, posOpenParen);

                    // Удаляем часть после '@' если есть
                    int atPos = name.IndexOf('@');
                    if (atPos != -1)
                    {
                        name = name.Substring(0, atPos);
                    }
                }
                else
                {
                    //name = line;
                }

                //if(name == "")
                //{
                //    int bp = 0;
                //}
                //if (name == "") { Console.WriteLine($"Warn! empty name at {i} : {line}"); continue; }
                if (name == "") { continue; }


                bool isFullyStandardName = ((name.StartsWith("nullsub_")) || (name == $"sub_{trimedHexAddr}"));
                bool _IsLowRenamed = (!isFullyStandardName && (name.Contains("nullsub_") || (name.EndsWith($"sub_{trimedHexAddr}"))));
                functions.Add(new FunctionInfo
                {
                    Name = name,
                    IdaAddress = addr,
                    IdaStringAddress = hexAddr,
                    FuncHeader = line,
                    ElfAddress = ((addr - _idaBase) + _elfHeaderSize),
                    CodeLinesCommentStart = i,
                    CodeLinesStart = j,
                    IsRenamed = !isFullyStandardName,
                    IsLowRenamed = _IsLowRenamed,
                });
            }

            //functions = functions.OrderBy(e => e.IdaAddress).ToList();
            //List<FunctionInfo> functionsByCode = functions.OrderBy(e => e.CodeLinesCommentStart).ToList();

            // Elf (calc func bytes size(nextptr-currfuncptr), read elf funcs bytes, code lines)
            for (int i = 0; i < functions.Count; i++)
            {
                //Console.WriteLine($"{i}/{functions.Count}");
                // calc bytes size (idapta next - idaptr curr) + load bytes + md5
                // calc code rows (start next - start curr) + load rows, после расчёта строк скоректировать вверх, найти } (\n, комменты между функциями)

                FunctionInfo current = functions[i];

                // Calculate function size in bytes
                uint nextAddr = (i < functions.Count - 1)
                    ? functions[i + 1].IdaAddress
                    : current.IdaAddress + 0x100; // Default size if last function
                current.Size = nextAddr - current.IdaAddress;

                // Read bytes from ELF file
                if (!_skipElf && (current.ElfAddress + current.Size <= binaryData.Length))
                {
                    current.Bytes = new byte[current.Size];
                    Array.Copy(binaryData, current.ElfAddress, current.Bytes, 0, current.Size);

                    // trim 0 in the end and resize? (space padding between funcs)
                    {
                        // Trim trailing zeros in groups of 4 bytes
                        int newLength = current.Bytes.Length;
                        while (newLength >= 4)
                        {
                            bool allZeros = true;
                            for (int j = 1; j <= 4; j++) { if (current.Bytes[newLength - j] != 0) { allZeros = false; break; } }
                            if (allZeros) { newLength -= 4; }
                            else { break; }
                        }
                        // If we trimmed any zeros, resize the array and update the size
                        if (newLength != current.Bytes.Length)
                        {
                            byte[] trimmedBytes = new byte[newLength];
                            Array.Copy(current.Bytes, 0, trimmedBytes, 0, newLength);
                            current.Bytes = trimmedBytes;
                            current.Size = (uint)newLength;
                        }
                    }

                    // Calculate MD5 hash
                    using (var md5 = System.Security.Cryptography.MD5.Create())
                    {
                        current.Md5Hash = BitConverter.ToString(md5.ComputeHash(current.Bytes)).Replace("-", "");
                    }
                }

                //// Calculate code lines using functionsByCode order (line-based)
                //int nextFuncIndexInCodeOrder = functionsByCode.IndexOf(current) + 1;
                //int nextCodeStart = (nextFuncIndexInCodeOrder < functionsByCode.Count)
                //    ? functionsByCode[nextFuncIndexInCodeOrder].CodeLinesStart
                //    : c_lines.Length;
                //int CodeLinesCount = nextCodeStart - current.CodeLinesStart;

                // Calculate code lines (line-based)
                int nextCodeStart = (i < functions.Count - 1)
                    ? functions[i + 1].CodeLinesStart
                    : c_lines.Length;
                int CodeLinesCount = nextCodeStart - current.CodeLinesStart;

                // Adjust code lines to include everything until the closing brace /\
                for (int j = current.CodeLinesStart + CodeLinesCount - 1; j >= current.CodeLinesStart; j--)
                {
                    if (j < c_lines.Length && c_lines[j].Contains('}'))
                    {
                        CodeLinesCount = (j - current.CodeLinesStart + 1);
                        break;
                    }
                }

                // Extract the actual code lines
                current.CodeLines = new List<string>();
                current.FuncsInto = new List<string>();
                for (int j = current.CodeLinesStart; j < current.CodeLinesStart + CodeLinesCount; j++)
                {
                    if (j < c_lines.Length)
                    {
                        if (j > current.CodeLinesStart && (!fast)) { current.FuncsInto.AddRange(SparseFuncsNames(RemoveComment(c_lines[j]))); }
                        current.CodeLines.Add(c_lines[j]);
                    }
                }
                current.IsFunctionEmpty = IsFunctionEmpty(current.CodeLines, true);
            }
            return functions;
        }

        public void Dump(IEnumerable<FunctionInfo> functions)
        {
            foreach (var f in functions)
            {
                Console.WriteLine($"Name: {f.Name}");
                Console.WriteLine($"IDA Address: 0x{f.IdaAddress:X8}");
                Console.WriteLine($"ELF Address: 0x{f.ElfAddress:X8}");
                Console.WriteLine($"Size: {f.Size}");
                Console.WriteLine($"MD5: {f.Md5Hash}");
                Console.WriteLine($"CodeLinesCommentStart: {f.CodeLinesCommentStart}");
                Console.WriteLine($"CodeLinesStart: {f.CodeLinesStart}");
                Console.WriteLine($"Renamed: {f.IsRenamed}");
                Console.WriteLine($"LowRenamed: {f.IsLowRenamed}");
                Console.WriteLine($"Empty: {f.IsFunctionEmpty}");
                Console.WriteLine("Code:");
                foreach (var line in f.CodeLines)
                    Console.WriteLine("    " + line);
                Console.WriteLine(new string('-', 60));
            }
        }

        //public static void SaveToBinaryFile(List<FunctionInfo> data, string filePath)
        //{
        //    //string md5Name;
        //    //using (var md5 = MD5.Create())
        //    //{
        //    //    byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(filePath));
        //    //    md5Name = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        //    //}
        //    //string finalPath = Path.Combine(Path.GetDirectoryName(filePath), md5Name + ".bin");
        //    string finalPath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetFileNameWithoutExtension(filePath) + ".bin");
        //    BinaryFormatter formatter = new BinaryFormatter();
        //    using (FileStream stream = new FileStream(finalPath, FileMode.Create))
        //    {
        //        formatter.Serialize(stream, data);
        //    }
        //}
        //public static List<FunctionInfo> LoadFromBinaryFile(string filePath)
        //{
        //    //string md5Name;
        //    //using (var md5 = MD5.Create())
        //    //{
        //    //    byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(filePath));
        //    //    md5Name = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        //    //}
        //    //string finalPath = Path.Combine(Path.GetDirectoryName(filePath), md5Name + ".bin");
        //    string finalPath = filePath;
        //    if (!File.Exists(finalPath)) { return new List<FunctionInfo>(); }
        //    BinaryFormatter formatter = new BinaryFormatter();
        //    using (FileStream stream = new FileStream(finalPath, FileMode.Open))
        //    {
        //        return (List<FunctionInfo>)formatter.Deserialize(stream);
        //    }
        //}

        public static void SaveToFile(List<FunctionInfo> functions, string filePath)
        {
            if (functions == null) throw new ArgumentNullException(nameof(functions));
            string json = JsonConvert.SerializeObject(functions, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }

        public static List<FunctionInfo> LoadFromFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Файл не найден", filePath);

            string json = File.ReadAllText(filePath);
            return JsonConvert.DeserializeObject<List<FunctionInfo>>(json)
                   ?? new List<FunctionInfo>();
        }
    }



    class Program
    {
        static void ProduseAsm1(List<FunctionInfo> vcs, List<FunctionInfo> three)
        {
            //{
            //    // Удаляем дубликаты из списка three
            //    three = three
            //        .GroupBy(x => x.Md5Hash)
            //        .Select(g => g.First())
            //        .ToList();

            //    // Удаляем дубликаты из списка vcs
            //    vcs = vcs
            //        .GroupBy(x => x.Md5Hash)
            //        .Select(g => g.First())

            //        .ToList();
            //    List<FunctionInfo> buff = new List<FunctionInfo>();
            //    foreach (var _3 in three)
            //    {
            //        if (_3.CodeLines.Count == 4 && _3.CodeLines[2].Contains("__asm { syscall }")) { buff.Add(_3); }
            //        //if (_3.CodeLines.Count == 5 && _3.CodeLines[3].Contains("__asm { syscall }")) { buff.Add(_3); }
            //    }
            //    Console.WriteLine($"c: {buff.Count}\n");

            //    foreach (var v in vcs)
            //    {
            //        foreach (var t in buff) // :/
            //        {
            //            if ((t.Md5Hash == v.Md5Hash) && (t.Name != v.Name))
            //            {
            //                //Console.WriteLine($"3 {t.IdaStringAddress},  v  {v.IdaStringAddress}");
            //                Console.WriteLine($"3 {t.Name},  v  {v.IdaStringAddress}");
            //            }
            //        }
            //    }
            //}


            //{
            //    foreach (var item in vcs)
            //    {
            //        bool cmp = false;
            //        foreach (var l in item.CodeLines)
            //        {
            //            if (l.Contains(" = 256;")) { cmp = true; break; }
            //        }
            //        if (cmp)
            //        {
            //            foreach (var l in item.CodeLines)
            //            {
            //                Console.WriteLine(l);
            //            }
            //            //return;
            //            Console.WriteLine();
            //        }
            //    }
            //}

            //foreach (var f in three)
            //{
            //    foreach (var c in f.CodeLines)
            //    {
            //        if (c.Contains("(220)"))
            //        {
            //            Console.WriteLine($"{f.Name} {c}");
            //        }
            //    }
            //}

            foreach (var f in vcs)
            {
                //if (!f.Name.Contains("CRunningScript::ProcessCommand_")) { continue; }
                foreach (var c in f.CodeLines)
                {
                    if (c.Contains("TheCamera.field_84C"))
                    {
                        Console.WriteLine($"{f.Name} {c}");
                    }
                }
            }
        }


        class reSrcOpNode : FunctionInfo
        {
            // script.cpp
            public int op_index; // 0
            public int op_case_row_index; // 0
            public int op_logical_index; // 0
            public string op_name; // COMMAND_NOP
            public int op_total_collect; // 0 (ivars+textip+etc)
            public int op_total_collect_count;
            public int op_total_storage; // 0
            public int op_total_storage_count;
            public bool op_total_err_parse; // wrong checksum
            public bool op_update_compare_flag; // UpdateCompareFlag()
            public List<string> op_case_code; // code
            public List<string> op_trimed_case_code; // code
            public bool inited;
            public string Mazahaka_Op_Name; // my name

            // vcs.c pseudo
            public int pseudo_total_collect; // 0 (ivars+textip+etc)
            public int pseudo_total_collect_count;
            public int pseudo_total_storage; // 0
            public int pseudo_total_storage_count;
            public bool pseudo_total_err_parse; // wrong checksum
            public bool pseudo_update_compare_flag; // UpdateCompareFlag()
            public List<string> pseudo_case; // code
            public reSrcOpNode() { op_case_code = new List<string>(); op_trimed_case_code = new List<string>(); pseudo_case = new List<string>(); }
        }

        static List<reSrcOpNode> ConvertFunctionInfoToReSrcOpNodes(List<FunctionInfo> vcsfunctions)
        {
            List<reSrcOpNode> result = new List<reSrcOpNode>();

            foreach (var func in vcsfunctions)
            {
                reSrcOpNode node = new reSrcOpNode();

                // Копируем свойства из FunctionInfo
                node.Name = func.Name;
                node.IdaStringAddress = func.IdaStringAddress;
                node.IdaAddress = func.IdaAddress;
                node.ElfAddress = func.ElfAddress;
                node.CodeLinesCommentStart = func.CodeLinesCommentStart;
                node.CodeLinesStart = func.CodeLinesStart;
                node.CodeLines = func.CodeLines;
                node.FuncsInto = func.FuncsInto;
                node.FuncsIntoIndicies = func.FuncsIntoIndicies;
                node.Bytes = func.Bytes;
                node.Size = func.Size;
                node.Md5Hash = func.Md5Hash;
                node.IsRenamed = func.IsRenamed;
                node.IsLowRenamed = func.IsLowRenamed;
                node.IsFunctionEmpty = func.IsFunctionEmpty;
                node.pseudo_case = func.CodeLines;

                // Устанавливаем специфичные для reSrcOpNode значения
                node.op_index = 0; // или другое значение по умолчанию/логике
                node.op_logical_index = 0;
                node.op_name = ""; // используем имя функции или значение по умолчанию
                node.op_total_collect = 0;
                node.op_total_collect_count = 0;
                node.op_total_storage = 0;
                node.op_total_storage_count = 0;
                node.op_total_err_parse = false;
                node.op_update_compare_flag = false;
                node.op_case_code = new List<string>();
                node.op_trimed_case_code = new List<string>();
                node.pseudo_case = new List<string>();

                result.Add(node);
            }

            return result;
        }

        static void reSrcParseScrIO(List<FunctionInfo> lfi_vcsfunctions)
        {
            List<reSrcOpNode> vcsfunctions = ConvertFunctionInfoToReSrcOpNodes(lfi_vcsfunctions);
            Console.WriteLine($"vcs func ida count: {vcsfunctions.Count}");

            // List<reSrcOpNode> revcsnodes;
            #region REVCS
            string headerFile = $"re\\ScriptCommands.h";
            string MazahakaHeaderFile = $"re\\MAZAHAKA_ScriptCommands.h";
            string casesFile = $"re\\Script.cpp";
            if (!File.Exists(headerFile) || !File.Exists(casesFile) || !File.Exists(MazahakaHeaderFile)) { Console.WriteLine($"!file"); return; }
            List<reSrcOpNode> revcsnodes = new List<reSrcOpNode>();

            // warn. Text colect, non parse index collect

            // 1. Read header and build command list
            string[] headerLines = File.ReadAllLines(headerFile);
            string[] MazahakaHeaderLines = File.ReadAllLines(MazahakaHeaderFile);
            if (headerLines.Length != MazahakaHeaderLines.Length) { Console.WriteLine("!eq mazahaka+revcs"); return; }
            int logical_index = 0;
            //foreach (string raw in headerLines)
            for (int i = 0; i < headerLines.Length; i++)
            {
                string raw = headerLines[i];
                // Trim spaces and tabs
                var line = raw.Trim().Replace(" ", "").Replace("\t", "");
                if (string.IsNullOrEmpty(line) || line.StartsWith("//"))
                    continue;

                // Expect: COMMAND_NAME=0xHEX,
                var eqPos = line.IndexOf('=');
                var commaPos = line.IndexOf(',');
                if (eqPos < 0 || commaPos < 0 || commaPos <= eqPos)
                    continue;

                var name = line.Substring(0, eqPos);
                var valStr = line.Substring(eqPos + 1, commaPos - eqPos - 1);

                // Parse hex or decimal
                int value;
                if (valStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    value = Convert.ToInt32(valStr.Substring(2), 16);
                else
                    value = int.Parse(valStr);

                reSrcOpNode node = new reSrcOpNode();
                node.op_index = value;
                node.op_logical_index = logical_index++;
                node.op_name = name;
                node.Mazahaka_Op_Name = MazahakaHeaderLines[i].Replace(" ", "").Replace("\t", "").Replace("\r", "").Replace("\n", "").Replace(",", "").Trim();
                if (node.Mazahaka_Op_Name.IndexOf("//") >= 0)
                {
                    node.Mazahaka_Op_Name = node.Mazahaka_Op_Name.Substring(0, node.Mazahaka_Op_Name.IndexOf("//"));
                }
                revcsnodes.Add(node);
            }


            // 2. Read .cpp and assign case code to nodes
            string[] cppLines = File.ReadAllLines(casesFile);
            reSrcOpNode currentNode = null;
            bool inCaseBody = false;
            List<int> rollback_cases_indices = new List<int>();
            //foreach (var raw in cppLines)
            for (int i = 0; i < cppLines.Length; i++)
            {
                string raw = cppLines[i];
                string line = raw.Trim().Replace(" ", "").Replace("\t", "");
                if (string.IsNullOrEmpty(line)) { continue; }
                // Detect new case
                if (line.StartsWith("case") && line.Contains(":"))
                {
                    string name = line.Substring(4, line.IndexOf(':') - 4);

                    //if(name == "COMMAND_CREATE_CHAR")
                    //{
                    //    int a = 0;
                    //}

                    if (revcsnodes.Find(n => n.op_name == name) != null)
                    {
                        currentNode = revcsnodes.Find(n => n.op_name == name);
                        if (inCaseBody)
                        {
                            rollback_cases_indices.Clear();
                            inCaseBody = false;
                        }
                        currentNode.op_case_row_index = i + 1;
                        rollback_cases_indices.Add(revcsnodes.IndexOf(currentNode));
                        continue;
                    }
                }
                // Add code line to current case
                if (currentNode != null)
                {
                    // добавляем строку в каждый из накопленных кейсов
                    foreach (var idx in rollback_cases_indices)
                    {
                        var n = revcsnodes[idx];
                        n.op_case_code.Add(raw);
                        n.op_trimed_case_code.Add(line);
                    }
                    // и теперь подтверждаем — мы в теле case
                    inCaseBody = true;
                    //currentNode.op_trimed_case_code.Add(line);
                    //currentNode.op_case_code.Add(raw);
                }
            }

            // 3. Очистка комментариев: удаляем полные строки и обрезаем inline-комментарии
            foreach (reSrcOpNode node in revcsnodes)
            {
                //if (node.op_name == "COMMAND_CALL")
                //if (node.op_index == 15)
                //{
                //    int t = 4;
                //}

                for (int j = node.op_trimed_case_code.Count - 1; j >= 0; j--)
                {
                    var trimmed = node.op_trimed_case_code[j];
                    if (trimmed.StartsWith("//"))
                    {
                        node.op_trimed_case_code.RemoveAt(j);
                        node.op_case_code.RemoveAt(j);
                    }
                    else
                    {
                        var raw = node.op_case_code[j];
                        int idx = raw.IndexOf("//");
                        if (idx >= 0)
                        {
                            node.op_case_code[j] = raw.Substring(0, idx);
                            node.op_trimed_case_code[j] = trimmed.Split(new[] { "//" }, StringSplitOptions.None)[0].Trim();
                        }
                    }
                }
            }

            // 4. Parse totals and update flag
            foreach (reSrcOpNode node in revcsnodes)
            {
                //if (node.op_index == 15)
                //{
                //    int t = 4;
                //}

                foreach (var line in node.op_trimed_case_code)
                {
                    //if (line.StartsWith("CollectParameters", StringComparison.Ordinal))
                    if (line.ToLower().Contains("CollectParameters(".ToLower()))
                    {
                        try
                        {
                            int start = line.IndexOf('(');
                            int comma1 = line.IndexOf(',', start + 1);
                            int comma2 = line.IndexOf(',', comma1 + 1);
                            int end = line.IndexOf(')', start + 1);
                            int valEnd = (comma2 != -1 && comma2 < end) ? comma2 : end;
                            string numStr = line.Substring(comma1 + 1, valEnd - comma1 - 1).Trim();
                            if (int.TryParse(numStr, out int count))
                            {
                                node.op_total_collect += count;
                                node.op_total_collect_count++;
                            }
                            else node.op_total_err_parse = true;
                        }
                        catch { node.op_total_err_parse = true; }
                    }
                    //else if (line.StartsWith("StoreParameters", StringComparison.Ordinal))
                    else if (line.ToLower().Contains("StoreParameters(".ToLower()))
                    {
                        try
                        {
                            int start = line.IndexOf('(');
                            int comma1 = line.IndexOf(',', start + 1);
                            int comma2 = line.IndexOf(',', comma1 + 1);
                            int end = line.IndexOf(')', start + 1);
                            int valEnd = (comma2 != -1 && comma2 < end) ? comma2 : end;
                            string numStr = line.Substring(comma1 + 1, valEnd - comma1 - 1).Trim();
                            if (int.TryParse(numStr, out int count))
                            {
                                node.op_total_storage += count;
                                node.op_total_storage_count++;
                            }
                            else node.op_total_err_parse = true;
                        }
                        catch { node.op_total_err_parse = true; }
                    }
                    //else if (line.StartsWith("UpdateCompareFlag", StringComparison.Ordinal))
                    else if (line.ToLower().Contains("UpdateCompareFlag(".ToLower())) // CRunningScript::UpdateCompareFlag(CPickuAM(3)));
                    {
                        node.op_update_compare_flag = true;
                    }
                }
            }
            #endregion

            #region PSEUDO
            Regex numberRegex = new Regex("(\\d+)\\s*(?:i64)?");
            for (int i = 0; i < revcsnodes.Count; i++)
            {
                // find him pseudo
                for (int j = 0; j < vcsfunctions.Count; j++)
                {
                    if (vcsfunctions[j].Name.Trim().StartsWith("CRunningScript::ProcessCommand_") &&
                        vcsfunctions[j].Name.Trim().Contains($"_{revcsnodes[i].op_index}_"))
                    { // init our re code data from pseudo
                        revcsnodes[i].Name = vcsfunctions[j].Name;
                        revcsnodes[i].IdaStringAddress = vcsfunctions[j].IdaStringAddress;
                        revcsnodes[i].IdaAddress = vcsfunctions[j].IdaAddress;
                        revcsnodes[i].ElfAddress = vcsfunctions[j].ElfAddress;
                        revcsnodes[i].CodeLinesCommentStart = vcsfunctions[j].CodeLinesCommentStart;
                        revcsnodes[i].CodeLinesStart = vcsfunctions[j].CodeLinesStart;
                        //revcsnodes[i].CodeLinesStart = vcsfunctions[j].CodeLinesStart;
                        revcsnodes[i].FuncHeader = vcsfunctions[j].FuncHeader;
                        revcsnodes[i].CodeLines = vcsfunctions[j].CodeLines;
                        revcsnodes[i].Bytes = vcsfunctions[j].Bytes;
                        revcsnodes[i].Size = vcsfunctions[j].Size;
                        revcsnodes[i].Md5Hash = vcsfunctions[j].Md5Hash;
                        revcsnodes[i].IsRenamed = vcsfunctions[j].IsRenamed;
                        revcsnodes[i].IsLowRenamed = vcsfunctions[j].IsLowRenamed;
                        revcsnodes[i].pseudo_case = vcsfunctions[j].CodeLines;

                        //Console.WriteLine(vcsfunctions[j].Name);
                        break;
                    }
                }
            }

            for (int i = 0; i < revcsnodes.Count; i++)
            {
                reSrcOpNode node = revcsnodes[i];
                // Initialize pseudo counters
                node.pseudo_total_collect = 0;
                node.pseudo_total_collect_count = 0;
                node.pseudo_total_storage = 0;
                node.pseudo_total_storage_count = 0;
                node.pseudo_total_err_parse = false;
                node.pseudo_update_compare_flag = false;

                //if(node.op_index == 723)
                //{
                //    int d = 0;
                //}

                // Parse pseudo-code lines for this command
                //foreach (var line in node.op_trimed_case_code) // revcs
                int[] upd_cmp_flag_passes = { 0, 0, 0, 0, 0, };
                foreach (var line in node.CodeLines) // ida vcs pseudo
                {
                    try
                    {
                        //if (line.StartsWith("CollectParameters(", StringComparison.Ordinal))
                        //{
                        //    // Extract the count argument
                        //    var parts = line.Substring(line.IndexOf('(') + 1)
                        //                    .Split(',');
                        //    if (parts.Length >= 2 && int.TryParse(parts[1].Trim(), out int count)) // part1   "4);"
                        //    {
                        //        node.pseudo_total_collect += count;
                        //        node.pseudo_total_collect_count++;
                        //    }
                        //    else node.pseudo_total_err_parse = true;
                        //}

                        //else if (line.StartsWith("StoreParameters(", StringComparison.Ordinal))
                        //{
                        //    var parts = line.Substring(line.IndexOf('(') + 1)
                        //                    .Split(',');
                        //    if (parts.Length >= 2 && int.TryParse(parts[1].Trim(), out int count))
                        //    {
                        //        node.pseudo_total_storage += count;
                        //        node.pseudo_total_storage_count++;
                        //    }
                        //    else node.pseudo_total_err_parse = true;
                        //}
                        if (line.Contains("CollectParameters(") || line.Contains("StoreParameters("))
                        {
                            bool isCollect = line.Contains("CollectParameters(");
                            int start = line.IndexOf('(') + 1;
                            int end = line.LastIndexOf(')');
                            if (start < 1 || end <= start)
                            {
                                node.pseudo_total_err_parse = true;
                                continue;
                            }

                            // Split into substrings by comma
                            var parts = line.Substring(start, end - start)
                                            .Split(',')
                                            .Select(p => p.Trim())
                                            .ToArray();

                            bool found = false;
                            foreach (var rawPart in parts)
                            {
                                // Skip parts with '+'
                                if (rawPart.Contains("+") || rawPart.Contains("_") || rawPart.Contains("->"))
                                    continue;

                                // Match pure number patterns with optional i64 suffix
                                // Examples: 0x09i64, 9i64, 0x9, 9
                                var token = rawPart;
                                // Strip i64 suffix if present
                                if (token.EndsWith("i64", StringComparison.OrdinalIgnoreCase))
                                    token = token.Substring(0, token.Length - 3);

                                // Check hex
                                int countVal;
                                if (Regex.IsMatch(token, "^0x[0-9A-Fa-f]+$"))
                                {
                                    if (!int.TryParse(token.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out countVal))
                                        continue;
                                }
                                else if (Regex.IsMatch(token, "^[0-9]+$"))
                                {
                                    if (!int.TryParse(token, out countVal))
                                        continue;
                                }
                                else
                                {
                                    continue;
                                }

                                // Successfully parsed a count
                                if (isCollect)
                                {
                                    node.pseudo_total_collect += countVal;
                                    node.pseudo_total_collect_count++;
                                }
                                else
                                {
                                    node.pseudo_total_storage += countVal;
                                    node.pseudo_total_storage_count++;
                                }
                                found = true;
                                break;
                            }

                            if (!found)
                                node.pseudo_total_err_parse = true;
                        }
                        else if (line.Contains("UpdateCompareFlag(")) // lol
                        {
                            node.pseudo_update_compare_flag = true;
                        }

                        // Detect inline compare logic: any use of AndOrState or CondResult implies UpdateCompare
                        //else if (line.Contains("->m_nAndOrState") || line.Contains("->m_bCondResult"))
                        //else if (line.Contains("m_nAndOrState") || line.Contains("m_bCondResult")) // CRunningScript* this
                        //{
                        //    node.pseudo_update_compare_flag = true;
                        //}
                        //else if (line.Contains("m_nAndOrState"))
                        //{
                        //    // Detect inlined compare logic by threshold substrings
                        //    if (line.Contains(">= 9") || line.Contains(">=9") ||
                        //        line.Contains(">= 0x9") || line.Contains(">=0x9") ||
                        //        line.Contains(">= 21") || line.Contains(">=21") ||
                        //        line.Contains(">= 0x15") || line.Contains(">=0x15"))
                        //    {
                        //        node.pseudo_update_compare_flag = true;
                        //    }
                        //}
                        else
                        {
                            string[] andor = { "m_nAndOrState", "->m_nAndOrState", };
                            string[] condres = { "m_bCondResult", "->m_bCondResult", };

                            string[] thr9 = { ">= 9", ">=9", ">= 0x9", ">=0x9", ">= 0x09", ">=0x09", };
                            string[] thr21 = { ">= 21", ">=21", ">= 0x15", ">=0x15", "<= 21", "<=21", "<= 0x15", "<=0x15",
                            "< 21", "<21", "> 0x15", ">0x15"};

                            foreach (var t in andor) { if (line.Contains(t)) { upd_cmp_flag_passes[3]++; break; } }
                            foreach (var t in condres) { if (line.Contains(t)) { upd_cmp_flag_passes[4]++; break; } }

                            foreach (var t in thr9) { if (line.Contains(t)) { upd_cmp_flag_passes[0]++; break; } }
                            foreach (var t in thr21) { if (line.Contains(t)) { upd_cmp_flag_passes[1]++; break; } }
                            if (line.Contains("--")) { upd_cmp_flag_passes[2]++; }

                            if ((upd_cmp_flag_passes[0] > 0 && upd_cmp_flag_passes[1] > 0 && upd_cmp_flag_passes[2] > 0)
                                || (upd_cmp_flag_passes[2] > 0 && upd_cmp_flag_passes[3] > 0 && upd_cmp_flag_passes[4] > 0)
                                )
                            {
                                node.pseudo_update_compare_flag = true;
                            }
                        }
                    }
                    catch { node.pseudo_total_err_parse = true; }
                }
            }

            #endregion

            //for (int i = 0; i < revcsnodes.Count; i++)
            //{
            //    reSrcOpNode n = revcsnodes[i];
            //    if(n.op_update_compare_flag && !n.pseudo_update_compare_flag) // in cases but not in ida (UpdateCompare)
            //    {
            //        Console.WriteLine($"{n.op_name} : coll={n.op_total_collect}, store={n.op_total_storage}," +
            //            $" err={n.op_total_err_parse}, updCompare={n.op_update_compare_flag}");
            //    }
            //}

            if (false)
            {
                string outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "op_pseudo_report.txt");
                using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
                {
                    int mode = 1;
                    if (mode == 0)
                    {
                        writer.WriteLine("OpName, MzhkOpName, Op_Coll, Op_Index, Op_CollCount, Op_Store, Op_StoreCount, Op_Err, Op_UpdCompare, " +
                                         "Pseudo_Coll, Pseudo_CollCount, Pseudo_Store, Pseudo_StoreCount, Pseudo_Err, Pseudo_UpdCompare");
                        for (int i = 0; i < revcsnodes.Count; i++)
                        {
                            reSrcOpNode n = revcsnodes[i];
                            //if (n.op_index == 15)
                            //{
                            //    int t = 4;
                            //}

                            // Фильтр: имеются флаг UpdateCompare и нет ошибки в парсинге псевдокода
                            //if (n.op_total_err_parse || n.pseudo_total_err_parse)
                            //if (n.op_update_compare_flag != n.pseudo_update_compare_flag) // UpdateCompareFlag
                            if (n.op_total_collect != n.pseudo_total_collect)
                            //if (n.op_total_storage != n.pseudo_total_storage)
                            {
                                writer.WriteLine($"{n.op_name}, {n.Mazahaka_Op_Name}, {n.op_index}, {n.op_total_collect}, {n.op_total_collect_count}, " +
                                                 $"{n.op_total_storage}, {n.op_total_storage_count}, {n.op_total_err_parse}, {n.op_update_compare_flag}, " +
                                                 $"{n.pseudo_total_collect}, {n.pseudo_total_collect_count}, {n.pseudo_total_storage}, " +
                                                 $"{n.pseudo_total_storage_count}, {n.pseudo_total_err_parse}, {n.pseudo_update_compare_flag}");
                            }
                        }
                    }
                    else if (mode == 1)
                    {
                        // Собираем все данные для определения максимальных длин
                        var allLines = new List<string[]>();
                        var headers = new string[] { "OpName", "MzhkOpName", "Op_Coll", "Op_Index", "Op_CollCount",
                                "Op_Store", "Op_StoreCount", "Op_Err", "Op_UpdCompare",
                                "Pseudo_Coll", "Pseudo_CollCount", "Pseudo_Store",
                                "Pseudo_StoreCount", "Pseudo_Err", "Pseudo_UpdCompare" };
                        allLines.Add(headers);

                        foreach (var n in revcsnodes)
                        {
                            // Фильтр: имеются флаг UpdateCompare и нет ошибки в парсинге псевдокода
                            //if (n.op_total_err_parse || n.pseudo_total_err_parse)
                            //if (n.op_update_compare_flag != n.pseudo_update_compare_flag) // UpdateCompareFlag
                            //if(n.op_total_collect != n.pseudo_total_collect)
                            //if (n.op_total_storage != n.pseudo_total_storage)

                            if ((n.op_total_err_parse || n.pseudo_total_err_parse) ||
                             (n.op_update_compare_flag != n.pseudo_update_compare_flag) || // UpdateCompareFlag
                             (n.op_total_collect != n.pseudo_total_collect) ||
                             (n.op_total_storage != n.pseudo_total_storage))

                            {
                                var line = new string[] {
                                n.op_name, n.Mazahaka_Op_Name, n.op_index.ToString(),
                                n.op_total_collect.ToString(), n.op_total_collect_count.ToString(),
                                n.op_total_storage.ToString(), n.op_total_storage_count.ToString(),
                                n.op_total_err_parse.ToString(), n.op_update_compare_flag.ToString(),
                                n.pseudo_total_collect.ToString(), n.pseudo_total_collect_count.ToString(),
                                n.pseudo_total_storage.ToString(), n.pseudo_total_storage_count.ToString(),
                                n.pseudo_total_err_parse.ToString(), n.pseudo_update_compare_flag.ToString()
                            };
                                allLines.Add(line);
                            }
                        }

                        // Определяем максимальную длину для каждого столбца
                        int[] columnWidths = new int[headers.Length];
                        for (int i = 0; i < headers.Length; i++)
                        {
                            columnWidths[i] = allLines.Max(line => line[i].Length) + 2; // +2 для отступов
                                                                                        //columnWidths[i] = Math.Max( allLines.Max(line => line[i].Length),headers[i].Length) + 2; // +2 для отступов
                        }

                        // Формируем строку формата
                        string format = "|";
                        for (int i = 0; i < columnWidths.Length; i++)
                        {
                            format += $" {{{i},-{columnWidths[i]}}}|";
                        }


                        int totalWidth = columnWidths.Sum() + columnWidths.Length + 1; // +1 для начального символа 

                        // Записываем заголовки
                        writer.WriteLine(new string('-', totalWidth));
                        writer.WriteLine(format, headers.Cast<object>().ToArray());
                        writer.WriteLine(new string('-', totalWidth));

                        // Записываем данные
                        foreach (var line in allLines.Skip(1))
                        {
                            writer.WriteLine(format, line.Cast<object>().ToArray());
                        }

                        writer.WriteLine(new string('-', totalWidth));
                    }
                    else if (mode == 2)
                    {
                        foreach (var n in revcsnodes)
                        {
                            if ((!n.Mazahaka_Op_Name.StartsWith("todo__comm")) && // no todo
                                (n.Mazahaka_Op_Name.ToUpper() == n.Mazahaka_Op_Name) && // no lower
                                (n.Mazahaka_Op_Name.Trim() != n.op_name.Trim())
                                )
                            {
                                Console.WriteLine($"{n.op_name}\t\t{n.Mazahaka_Op_Name}  {n.op_index}");
                            }
                        }
                    }
                }
            }


            //string pops = "bin\\vcsiplayer.txt";
            //int[] ops = File.ReadAllLines(pops).Where(x => x.Trim() != "").Select(x => int.Parse(x)).ToArray();
            //foreach (int op in ops)
            //{
            //    reSrcOpNode f = revcsnodes.Where(x => (x.Name != null) && x.Name.Contains("CRunningScript::ProcessCommand_") && x.Name.Contains($"_{op}_")).FirstOrDefault();
            //    bool isppseudo = false;
            //    bool isprevcs = false;
            //    for (int i = 0; i < f.CodeLines.Count; i++)
            //    {
            //        //if (f.CodeLines[i].Contains("CPed::IsPlayer")) { isppseudo = true; break; }
            //        if (f.CodeLines[i].Contains("IsPlayer")) { isppseudo = true; break; }
            //    }
            //    for (int i = 0; i < f.op_case_code.Count; i++)
            //    {
            //        if (f.op_case_code[i].Contains("IsPlayer")) { isprevcs = true; break; }
            //    }
            //    //if (isppseudo && !isprevcs) { Console.WriteLine(f.op_name); }
            //    if (isppseudo) { Console.WriteLine($"{op}: {f.op_name}"); }

            //    //Console.WriteLine($"{op} " + f.Name);
            //}
            ////foreach (reSrcOpNode item in revcsnodes)
            ////{
            ////    if(item.Name?.Contains("CRunningScript::ProcessCommand_") != null)
            ////    {
            ////        Console.WriteLine(item.Name);
            ////    }
            ////}
            ///


            foreach (reSrcOpNode item in revcsnodes)
            {
                //if (item.Name?.Contains("CRunningScript::ProcessCommand_") != null)
                {
                    string revcvs_command_name = item.op_name; // nop
                    int op_index = item.op_index; // 0
                    List<string> revcs_case = item.op_trimed_case_code;
                    List<string> pseudo_case = item.pseudo_case;

                    //Console.WriteLine($"{revcvs_command_name} {op_index}");

                    bool floatcast = IsExistsSubstr(pseudo_case, "float*", true, true);
                    bool isfloatincase = IsExistsSubstr(revcs_case, "_FLOAT_", true, true) || IsExistsSubstr(revcs_case, "ET_VECTOR", true, true);
                    // int dafault
                    if(floatcast && !isfloatincase) // missed FLOAT ARG IN REVCS
                        Console.WriteLine($"{revcvs_command_name} {op_index} [pseudo: floatcast, revcs: non _FLOAT_]");
                    if (!floatcast && isfloatincase) // wrong FLOAT ARG IN REVCS
                        Console.WriteLine($"{revcvs_command_name} {op_index} [pseudo: nonfloat, revcs: _FLOAT_]");
                }
            }




            Console.WriteLine($"ok");
            return;
            // TODO: subparse vcsfunctions on collect, stroage, err flag, updcomp(придумай, может быть не this crunning поля) + расширение


            for (int i = 0; i < revcsnodes.Count; i++)
            {
                reSrcOpNode n = revcsnodes[i];
                Console.WriteLine($"{n.op_name} : idx={n.op_index}, collect={n.op_total_collect}, storage={n.op_total_storage}," +
                    $" error={n.op_total_err_parse}, updateCompare={n.op_update_compare_flag}");
                //Console.WriteLine($"{revcsnodes[i].op_name} : {revcsnodes[i].op_index}   code: {revcsnodes[i].op_case_code.Count}");
                foreach (var c in revcsnodes[i].op_case_code) { Console.WriteLine(c); }
                Console.WriteLine();
            }

            Console.WriteLine($"ok");
        }



        class SimpleFunc
        {
            public string Header { get; set; }
            public List<string> Code { get; set; } = new List<string>();
            public int FuncStartRow { get; set; }
        }
        static List<SimpleFunc> ParseFunctions(string filePath)
        {
            var lines = File.ReadAllLines(filePath).ToList();
            var result = new List<SimpleFunc>();

            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i];
                // Поиск заголовка функции
                if (line.Contains("cPedCommentsManager::"))
                {
                    var func = new SimpleFunc { FuncStartRow = i + 1 };
                    // Собираем заголовок, возможно он занимает несколько строк
                    var headerLines = new List<string>();
                    while (i < lines.Count && !lines[i].Contains("{"))
                    {
                        headerLines.Add(lines[i]);
                        i++;
                    }
                    // Добавляем строку с открывающей фигурной скобкой
                    if (i < lines.Count && lines[i].Contains("{"))
                    {
                        headerLines.Add(lines[i]);
                    }
                    func.Header = string.Join(" ", headerLines).Trim();

                    // Теперь собираем тело функции по подсчету скобок
                    int braceCount = 0;
                    // Считаем все открывающие и закрывающие скобки в headerLines
                    braceCount += headerLines.Sum(l => l.Count(c => c == '{'));
                    braceCount -= headerLines.Sum(l => l.Count(c => c == '}'));

                    i++;
                    // Собираем код до балансировки скобок
                    while (i < lines.Count && braceCount > 0)
                    {
                        string codeLine = lines[i];
                        func.Code.Add(codeLine);
                        braceCount += codeLine.Count(c => c == '{');
                        braceCount -= codeLine.Count(c => c == '}');
                        i++;
                    }

                    result.Add(func);
                }
            }

            return result;
        }

        static bool IsExistsSubstr(List<string> rows, string search, bool withoutspace = false, bool checkcase = false)
        {
            if (search.Trim() == "")
                return false;

            foreach (string s in rows)
            {
                if ((checkcase ? s : s.ToLower()).Contains((checkcase ? search : search.ToLower())))
                    return true;
                if (withoutspace && (checkcase ? s : s.ToLower()).Replace(" ", "").Contains((checkcase ? search : search.ToLower()).Replace(" ", "")))
                    return true;
            }
            return false;
        }
        static (string, int) IsExistsGetSubstr(List<string> rows, string search, bool withoutspace = false)
        {
            if (search.Trim() == "")
                return ("", 0);

            for (int i = 0; i < rows.Count; i++)
            {
                if (rows[i].ToLower().Contains(search.ToLower()))
                    return (rows[i], i);
                if (withoutspace && rows[i].ToLower().Replace(" ", "").Contains(search.ToLower().Replace(" ", "")))
                    return (rows[i], i);
            }
            return ("", 0);
        }
        private static string ExtractClassName(string fullFunctionName)
        {
            if (string.IsNullOrWhiteSpace(fullFunctionName))
                return string.Empty;
            var parts = fullFunctionName.Split(new[] { "::" }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
                return parts[parts.Length - 2];
            return string.Empty;
        }
        static List<(string, int)> GetClassCounts(List<FunctionInfo> selectedList)
        {
            if (selectedList.Count == 0)
                return new List<(string, int)>();

            var classGroups = selectedList.Select(x => x.Name)
                .Where(name => !string.IsNullOrWhiteSpace(name) && name.Contains("::"))
                .Select(ExtractClassName)
                .Where(className => !string.IsNullOrEmpty(className))
                .GroupBy(className => className)
                .Select(group => (className: group.Key, count: group.Count()))
                .OrderByDescending(x => x.count)
                .ThenBy(x => x.className)
                .ToList();

            return classGroups;
        }
        static (bool, FunctionInfo) GetFunction(ref List<FunctionInfo> funcs, string name, bool checkcase = false)
        {
            if (name.Trim() == "")
                return (false, new FunctionInfo());

            foreach (FunctionInfo f in funcs)
            {
                if ((checkcase ? f.Name : f.Name.ToLower()).Contains((checkcase ? name : name.ToLower())))
                    return (true, f);
            }
            return (false, new FunctionInfo());
        }
        static bool IsExistsFunctionInList(List<FunctionInfo> funcs, string pat, bool lowercheck = true, bool startswith = true) // похоже
        {
            foreach (FunctionInfo f in funcs)
            {
                string functionName = f.Name.Trim();
                string pattern = pat.Trim();
                if (lowercheck)
                {
                    functionName = functionName.ToLower();
                    pattern = pattern.ToLower();
                }
                if (startswith)
                {
                    if (functionName.StartsWith(pattern))
                        return true;
                }
                else
                {
                    if (functionName.Contains(pattern))
                        return true;
                }
            }
            return false;
        }


        class Trace // func node
        {
            public class TraceInfo
            {
                public int traceSoundID;
                public int ps2Sfx;
                public int revcsSfx;
                public int phraseOffset;
            }

            public string funcName;
            public List<TraceInfo> info;
            public bool hasMale;
            public bool hasFemale;
            public int totalCases;

            public static List<Trace> ParseLog(string path)
            {
                var lines = File.ReadAllLines(path);
                // словарь для группировки по funcName
                var dict = new Dictionary<string, Trace>(StringComparer.OrdinalIgnoreCase);

                // пропускаем заголовок (линия 0)
                for (int i = 1; i < lines.Length; i++)
                {
                    var line = lines[i].Trim();
                    if (string.IsNullOrEmpty(line))
                        continue;

                    // разбиваем по запятой
                    var parts = line.Split(',');
                    if (parts.Length < 8)
                        continue;

                    var func = parts[0].Trim();
                    int traceSoundID = int.Parse(parts[1].Trim());
                    int ps2Sfx = int.Parse(parts[2].Trim());
                    int revcsSfx = int.Parse(parts[3].Trim());
                    int phraseOffset = int.Parse(parts[4].Trim());
                    bool triggerFemale = parts[5].Trim() == "1";
                    bool triggerMale = parts[6].Trim() == "1";
                    int total = int.Parse(parts[7].Trim());

                    // получаем или создаём новый Trace для данной функции
                    Trace trace;
                    if (!dict.TryGetValue(func, out trace))
                    {
                        trace = new Trace
                        {
                            funcName = func,
                            info = new List<TraceInfo>(),
                            hasFemale = false,
                            hasMale = false,
                            totalCases = total  // сохраняем «total» из первой строки
                        };
                        dict.Add(func, trace);
                    }

                    // добавляем запись в список
                    trace.info.Add(new TraceInfo
                    {
                        traceSoundID = traceSoundID,
                        ps2Sfx = ps2Sfx,
                        revcsSfx = revcsSfx,
                        phraseOffset = phraseOffset
                    });

                    // объединяем флаги
                    trace.hasFemale = trace.hasFemale || triggerFemale;
                    trace.hasMale = trace.hasMale || triggerMale;
                    // (если «total» в последующих строках отличается, можно здесь проверить и выдать предупреждение)
                }

                // возвращаем список всех Trace
                return dict.Values.ToList();
            }
        }

        static void ProcessSfxVariants(IEnumerable<string> codeLines, IEnumerable<string> ps2sfxs)
        {


            //        SFX_VIC_PISSED_OFF_PULL_GUN_28_0,
            //SFX_VIC_PISSED_OFF_PULL_GUN_29_0,
            //SFX_VIC_PISSED_OFF_PULL_GUN_30_0,
            ////3877-3901 pissed off shoot
            //SFX_VIC_PISSED_OFF_SHOOT_01_0,
            //SFX_VIC_PISSED_OFF_SHOOT_02_0,
            //SFX_VIC_PISSED_OFF_SHOOT_03_0,
            //SFX_VIC_PISSED_OFF_SHOOT_04_0,
            //SFX_VIC_PISSED_OFF_SHOOT_05_0,
            //SFX_VIC_PISSED_OFF_SHOOT_06_0,
            //SFX_VIC_PISSED_OFF_SHOOT_07_0,
            //SFX_VIC_PISSED_OFF_SHOOT_08_0,
            //SFX_VIC_PISSED_OFF_SHOOT_09_0,
            //SFX_VIC_PISSED_OFF_SHOOT_10_0,
            //SFX_VIC_PISSED_OFF_SHOOT_11_0,
            //SFX_VIC_PISSED_OFF_SHOOT_12_0,
            //SFX_VIC_PISSED_OFF_SHOOT_13_0,
            //SFX_VIC_PISSED_OFF_SHOOT_14_0,
            //SFX_VIC_PISSED_OFF_SHOOT_15_0,
            //SFX_VIC_PISSED_OFF_SHOOT_16_0,
            //SFX_VIC_PISSED_OFF_SHOOT_17_0,
            //SFX_VIC_PISSED_OFF_SHOOT_18_0,
            //SFX_VIC_PISSED_OFF_SHOOT_19_0,
            //SFX_VIC_PISSED_OFF_SHOOT_20_0,
            //SFX_VIC_PISSED_OFF_SHOOT_21_0,
            //SFX_VIC_PISSED_OFF_SHOOT_22_0,
            //SFX_VIC_PISSED_OFF_SHOOT_23_0,
            //SFX_VIC_PISSED_OFF_SHOOT_24_0,
            //SFX_VIC_PISSED_OFF_SHOOT_25_0,
            //SFX_VIC_PISSED_OFF_SHOOT_26_0,
            //SFX_VIC_PISSED_OFF_SHOOT_27_0,
            //SFX_VIC_PISSED_OFF_SHOOT_28_0,
            //        SFX_BFOST_FIGHT_2,
            //SFX_BFOST_FIGHT_3,
            //SFX_BFOST_PICK_UP_CASH_1, //unused
            //SFX_BFOST_PICK_UP_CASH_2, //unused
            //SFX_BFOST_PICK_UP_CASH_3, //unused
            //SFX_BFOST_GUN_THREATENED_1,
            //SFX_BFOST_GUN_THREATENED_2,
            //SFX_BFOST_JACKED_CAR_1,
            //SFX_BFOST_JACKED_CAR_2,
            //SFX_BFOST_JACKED_CAR_3,
            //SFX_BFOST_SHOCKED_1,
            ////186-209 (bfotr)
            //SFX_BFOTR_BUMP_1,
            //SFX_BFOTR_BUMP_2,
            //SFX_BFOTR_BUMP_3,
            //SFX_BFOTR_CHAT_1,
            //SFX_BFOTR_CHAT_2,
            //SFX_BFOTR_CHAT_3,
            //SFX_BFOTR_CHAT_4,
            //SFX_BFOTR_CRASH_CAR_1,
            //SFX_BFOTR_CRASH_CAR_2,
            //SFX_BFOTR_DODGE_1,
            //SFX_BFOTR_DODGE_2,
            //SFX_BFOTR_DRIVER_BLOCKED_1,
            //SFX_BFOTR_DRIVER_BLOCKED_2,
            //SFX_BFOTR_FIGHT_1,
            //SFX_BFOTR_FIGHT_2,


            foreach (var row in codeLines)
            {
                //if (row.Contains("SFX_VIC_"))
                //    continue;

                // 1) Находим, какой SFX встречается в строке
                string foundSfx = "";
                foreach (string s in ps2sfxs)
                {
                    if(row.Contains($"{s}, "))
                    {
                        foundSfx = s;
                        break;
                    }
                }
                //string foundSfx = ps2sfxs.FirstOrDefault(sfx => row.Contains(sfx));
                if (foundSfx == null || foundSfx == "")
                    continue;

                // 2) Извлекаем аргумент (последнее число перед ')')
                int arg;
                {
                    int idxParen = row.LastIndexOf(')');
                    int idxComma = row.LastIndexOf(',', idxParen - 1);
                    string argText = row.Substring(idxComma + 1, idxParen - idxComma - 1).Trim();
                    if (!int.TryParse(argText, out arg))
                    {
                        Console.WriteLine($"[WARN] Не удалось распознать аргумент: «{argText}» в строке:\n  {row}");
                        continue;
                    }
                }

                // 3) Извлекаем индекс (число в конце foundSfx)
                int index;
                string sfxBase;
                bool hasUnderscore;
                bool hasLeadingZero;
                {
                    int i = foundSfx.Length - 1;
                    // идём с конца, пока цифры
                    while (i >= 0 && char.IsDigit(foundSfx[i]))
                        i--;
                    // [i] — первый не-цифровой символ перед цифрами
                    int digitsStart = i + 1;
                    string digitsPart = foundSfx.Substring(digitsStart);
                    if (!int.TryParse(digitsPart, out index))
                    {
                        Console.WriteLine($"[WARN] Не удалось распознать индекс в SFX: «{foundSfx}»");
                        continue;
                    }

                    // база — всё до цифр (может заканчиваться на '_')
                    hasUnderscore = (i >= 0 && foundSfx[i] == '_');
                    sfxBase = hasUnderscore
                        ? foundSfx.Substring(0, i)    // убираем '_'
                        : foundSfx.Substring(0, digitsStart);

                    // определяем, было ли ведущее '0'
                    hasLeadingZero = digitsPart.Length > 1 && digitsPart[0] == '0';
                }

                // 4) Формируем два кандидата в том же стиле:
                //    текущий = для arg
                //    следующий = для arg+1
                string fmtArg = hasLeadingZero ? arg.ToString("D" + (foundSfx.Length - sfxBase.Length - (hasUnderscore ? 1 : 0)))
                                               : arg.ToString();
                string fmtNextArg = hasLeadingZero
                    ? (arg + 1).ToString("D" + (foundSfx.Length - sfxBase.Length - (hasUnderscore ? 1 : 0)))
                    : (arg + 1).ToString();

                string sep = hasUnderscore ? "_" : "";
                string sfxCurrent = $"{sfxBase}{sep}{fmtArg}";
                string sfxNext = $"{sfxBase}{sep}{fmtNextArg}";

                if (row.Contains("SFX_VIC_") && row.Contains("_01_"))
                {
                    sfxCurrent = foundSfx.Replace("_01_", $"{(arg > 9 ? $"_{arg}_" : $"_0{arg}_")}"); // hotfix
                }

                // 5) Проверяем наличие в списке
                if (!ps2sfxs.Contains(sfxCurrent))
                    Console.WriteLine($"[MISS] Не найден: {sfxCurrent}");

                if (ps2sfxs.Contains(sfxNext))
                    Console.WriteLine($"[INFO] Обнаружен неиспользованный: {sfxNext}");
            }
        }

        static bool IsVectorStringsEq(List<string> A, List<string> B, bool trim, bool lower)
        {
            // Проверка на null
            if (A == null || B == null)
            {
                return A == B; // Возвращаем true, если оба null
            }

            // Проверка на одинаковую длину списков
            if (A.Count != B.Count)
            {
                return false;
            }

            // Цикл для сравнения каждого элемента
            for (int i = 0; i < A.Count; i++)
            {
                string strA = A[i];
                string strB = B[i];

                // Проверка на null элементов
                if (strA == null || strB == null)
                {
                    if (strA != strB)
                    {
                        return false;
                    }
                    continue;
                }

                // Применяем trim, если нужно
                if (trim)
                {
                    strA = strA.Trim();
                    strB = strB.Trim();
                }

                // Применяем lower, если нужно
                if (lower)
                {
                    strA = strA.ToLower();
                    strB = strB.ToLower();
                }

                // Сравниваем строки
                if (strA != strB)
                {
                    return false;
                }
            }

            return true;
        }

        static void audioTest(List<FunctionInfo> vcsfunctions)
        {
            string tracelogPath = ".\\c\\TRACE.TXT";
            List<Trace> trace = Trace.ParseLog(tracelogPath);

            string audioPath = ".\\c\\TEST.C"; //revcs code (tested code)
            //List<string> code = File.ReadAllLines(audioPath).ToList();
            //Console.WriteLine($"total: {code.Count}");
            //for (int i = 0; i < code.Count; i++)
            //{
            //    Console.WriteLine($"{code[i]}");
            //}

            //List<string> sfxs = File.ReadAllLines(".\\c\\sfx.h").ToList();
            List<string> ps2sfxs = File.ReadAllLines(".\\c\\sfx.h")
           // 1) удаляем строки, которые после TrimStart() начинаются с "//"
           .Select(line => line.TrimStart())
           .Where(line => !line.StartsWith("//"))
           // 2) убираем inline‑комментарии: всё после "//"
           .Select(line =>
           {
               int _idx = line.IndexOf("//", StringComparison.Ordinal);
               return _idx >= 0 ? line.Substring(0, _idx) : line;
           })
           // 3) разбиваем по запятой и берём левую часть
           .Select(line =>
           {
               var parts = line.Split(new[] { ',' }, StringSplitOptions.None);
               return parts.Length > 0 ? parts[0].Trim() : string.Empty;
           })
           // 4) отбрасываем пустые
           .Where(token => !string.IsNullOrEmpty(token))
           .ToList();


            List<SimpleFunc> functions = ParseFunctions(audioPath);
            Console.WriteLine($"total: {functions.Count}");
            Console.WriteLine($"ps2sfxs: {ps2sfxs.Count}");
            Console.WriteLine($"trace: {trace.Count}");
            int idx = 0;
            foreach (var f in functions) // revcs funcs
            {
                Match match = Regex.Match(f.Header, @"(?<=::)\w+(?=\s*\()");
                string name = match.Success ? match.Value : "";
                if (name == "")
                    continue;
                //Console.WriteLine(name);

                //if (name.Contains("GetMissionTalkSfx_29"))
                //{
                //    int t = 4;
                //}

                {
                    if (name.Contains("GetMissionTalkSfx"))
                        continue;


                    //foreach (string row in f.Code)
                    //{
                    //    bool findsfx = false;
                    //    foreach (string sfx in ps2sfxs)
                    //    {
                    //        if(row.Contains(sfx))
                    //        {
                    //            findsfx = true;
                    //            break;
                    //        }
                    //    }
                    //    if(findsfx)
                    //    { // extract index and arg
                    //        //  // AudioManager.GetPhrase(sfx, ped->m_lastComment, SFX_VIC_ANGRY_BUSTED_01, 5); // extract 1 and 5
                    //        //  // AudioManager.GetPhrase(sfx, ped->m_lastComment, SFX_VIC_ANGRY_CALM1, 5); // 1 and 5
                    //        //  // AudioManager.GetPhrase(sfx, ped->m_lastComment, SFX_VIC_ANGRY_CALM_2, 5); // 2 and 5
                    //    }
                    //}

                    //foreach (string row in f.Code)
                    //{
                    //    // пропускаем ненужные строки
                    //    if (name.Contains("GetMissionTalkSfx"))
                    //        continue;

                    //    bool findsfx = ps2sfxs.Any(sfx => row.Contains(sfx));
                    //    if (!findsfx)
                    //        continue;

                    //    // шаблон: захватываем число после подчёркивания (_\d+), 
                    //    // и второе число перед закрывающей скобкой аргумента , 5)
                    //    var pattern = @".*?_(\d+).*?,\s*(\d+)\)";
                    //    var mmatch = Regex.Match(row, pattern);
                    //    if (mmatch.Success)
                    //    {
                    //        // C#7.3 позволяет так:
                    //        int iindex = int.Parse(mmatch.Groups[1].Value);
                    //        int arg = int.Parse(mmatch.Groups[2].Value);

                    //        // Или сразу через кортеж:
                    //        // (int index, int arg) = 
                    //        //     (int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value));

                    //        Console.WriteLine($"Index = {iindex}, Arg = {arg}");
                    //        // Делаем с ними что надо…
                    //    }
                    //}

                    ProcessSfxVariants(f.Code, ps2sfxs);
                    //foreach (string row in f.Code)
                    //{
                    //    // пропускаем специальные случаи
                    //    if (name.Contains("GetMissionTalkSfx"))
                    //        continue;

                    //    // ищем, какой именно sfx из списка встретился в этой строке
                    //    string foundSfx = ps2sfxs.FirstOrDefault(sfx => row.Contains(sfx));
                    //    if (foundSfx == null)
                    //        continue;

                    //    // парсим два числа: первое после подчёркивания, второе — второй аргумент метода
                    //    var callPattern = new Regex(@".*?_(\d+).*?,\s*(\d+)\)");
                    //    var callMatch = callPattern.Match(row);
                    //    if (!callMatch.Success)
                    //        continue;

                    //    int _index = int.Parse(callMatch.Groups[1].Value);
                    //    int arg = int.Parse(callMatch.Groups[2].Value);

                    //    // базовое имя без цифр/нижнего подчёркивания в конце:
                    //    var basePattern = new Regex(@"^(.*?)(?:[_\d]+)?$");
                    //    string sfxBase = basePattern.Match(foundSfx).Groups[1].Value;

                    //    // три варианта имени
                    //    var variants = new[]
                    //    {
                    //        $"{sfxBase}{arg}",
                    //        $"{sfxBase}_{arg}",
                    //        $"{sfxBase}_{arg:D2}"
                    //    };

                    //    // ищем каждый вариант в коде
                    //    var hits = variants.Where(v => f.Code.Any(r => r.Contains(v))).ToList();

                    //    if (hits.Count == 0)
                    //    {
                    //        //Console.WriteLine($"[WARN] Для базового '{sfxBase}' с аргументом {arg} не найдено ни одного варианта: {string.Join(", ", variants)}");
                    //        continue;
                    //    }

                    //    // нашли хотя бы один — теперь пробуем найти «неиспользованную» фразу
                    //    // собираем все суффиксные цифры, которые уже есть в коде для этого base
                    //    var numberPattern = new Regex($@"\b{Regex.Escape(sfxBase)}[_]?0*([0-9]+)\b");
                    //    var allNumbers = new List<int>();
                    //    foreach (var codeLine in f.Code)
                    //    {
                    //        foreach (Match m in numberPattern.Matches(codeLine))
                    //        {
                    //            allNumbers.Add(int.Parse(m.Groups[1].Value));
                    //        }
                    //    }

                    //    int maxNum = allNumbers.Count > 0 ? allNumbers.Max() : arg;
                    //    int nextNum = maxNum + 1;
                    //    string nextVariant = $"{sfxBase}_{nextNum:D2}";

                    //    // проверяем, есть ли такой «свежий» вариант в коде
                    //    bool existsNext = f.Code.Any(r => r.Contains(nextVariant));
                    //    if (existsNext)
                    //    {
                    //        Console.WriteLine($"[INFO] Обнаружена неиспользованная фраза: {nextVariant} (max существующих = {maxNum})");
                    //    }
                    //}

                }
                continue; // пока не нужен pseudo


                // ищем псевдо
                int index = -1;
                for (int i = 0; i < vcsfunctions.Count; i++)
                {
                    if(vcsfunctions[i].Name.Trim().ToLower().Contains(name.Trim().ToLower()))
                    {
                        index = i;
                        break;
                    }
                }

                // у нас есть pseudo + tested src
                if (index > -1) // pseudo index
                {
                    // 1. test AudioManager.GetPhrase  N);
                    // 2. test AudioManager.GetGeneric +++++++++++++++++++++++++++
                    // 3. test sfx names (all h + serach pseudo+tested) +++++++++++++++
                    // 4. ?test sound? done pseudo enum??????

                    //Console.WriteLine($"{idx} " + vcsfunctions[index].FuncHeader);
                    bool check = false;

                    //foreach (string s in f.Code)
                    //{
                    //    //if(s.ToLower().Contains("AudioManager.GetGeneric".ToLower()))
                    //    //{
                    //    //}
                    //}

                    // test GENERIC FEMALE
                    //bool isFt = IsExistsSubstr(f.Code, "GetGenericFemaleTalkSfx");
                    //bool isMt = IsExistsSubstr(f.Code, "GetGenericMaleTalkSfx");
                    //bool isFp = IsExistsSubstr(vcsfunctions[index].CodeLines, "GetGenericFemaleTalkSfx");
                    //bool isMp = IsExistsSubstr(vcsfunctions[index].CodeLines, "GetGenericMaleTalkSfx");

                    //if((isFt && !isFp) || (!isFt && isFp))
                    //    Console.WriteLine("err 1 in " + f.Header);
                    //if ((isMt && !isMp) || (!isMt && isMp))
                    //    Console.WriteLine("err 2 in " + f.Header);

                    //// test sfx names
                    //foreach (var curr_sfx in ps2sfxs)
                    //{
                    //    bool isSt = IsExistsSubstr(f.Code, curr_sfx);
                    //    bool isSp = IsExistsSubstr(vcsfunctions[index].CodeLines, curr_sfx);
                    //    if(isSt != isSp)
                    //       Console.WriteLine("err in " + f.Header);
                    //}

                    // test phrase cnt
                    // ищем лог
                    int tliidx = -1;
                    for (int tli = 0; tli < trace.Count; tli++)
                    {
                        if (f.Header.ToLower().Contains(trace[tli].funcName.ToLower() + "("))
                        {
                            tliidx = tli;
                            break;
                        }
                    }
                    if (tliidx < 0)
                        continue;

                    foreach (var trce in trace[tliidx].info)
                    {
                        //if(trace[tliidx].funcName.Contains("GetMissionTalkSfx_29"))
                        //{
                        //    int t = 4;
                        //}
                        string sfxname = ps2sfxs[trce.ps2Sfx];
                        string traceback = $"{sfxname}, {trce.phraseOffset}";
                        //Console.WriteLine(traceback);
                        bool isTrace = IsExistsSubstr(f.Code, traceback);
                        bool isMission = f.Header.Contains("GetMissionTalk");

                        if(isMission)
                            isTrace = IsExistsSubstr(f.Code, sfxname); // offset 3

                        if(!isTrace)
                            Console.WriteLine($"err traceback in {f.Header} : {traceback}");
                    }
                    Console.WriteLine($"{trace[tliidx].funcName} done!");

                }


                //Console.WriteLine(f.Header);
                ++idx;
            }


        }

        public class ClassInfo
        {
            public string ClassName { get; set; }
            public List<string> Methods { get; set; } = new List<string>();
        }

        static public List<ClassInfo> ParseClasses(string filePath)
        {
            var classes = new List<ClassInfo>();
            ClassInfo currentClass = null;

            foreach (var line in File.ReadAllLines(filePath).Where(l => !string.IsNullOrWhiteSpace(l)))
            {
                if (line.StartsWith("Class "))
                {
                    currentClass = new ClassInfo
                    {
                        ClassName = line.Substring("Class ".Length).Trim()
                    };
                    classes.Add(currentClass);
                }
                else if (currentClass != null && line.StartsWith("\t"))
                {
                    var method = line.Trim();
                    if (!string.IsNullOrEmpty(method))
                    {
                        currentClass.Methods.Add(method);
                    }
                }
            }

            return classes;
        }
        static public void SaveClasses(string filePath, List<ClassInfo> classes)
        {
            using (var writer = new StreamWriter(filePath))
            {
                foreach (var classInfo in classes)
                {
                    writer.WriteLine($"Class {classInfo.ClassName}");

                    foreach (var method in classInfo.Methods)
                    {
                        writer.WriteLine($"\t{method}");
                    }

                    writer.WriteLine();
                    writer.WriteLine();
                }
            }
        }

        static List<FunctionInfo> BuildTree(List<FunctionInfo> funcs)
        {
            for (int i = 0; i < funcs.Count; i++)
            {
                //Console.WriteLine($"{i}");
                for (int j = 0; j < funcs[i].CodeLines.Count; j++)
                {
                    if (j == 0) { continue; } // func header
                    for (int k = 0; k < funcs.Count; k++)
                    {
                        if (Parser.RemoveComment(funcs[i].CodeLines[j].Trim()).Contains(funcs[k].Name.Trim()))
                        {
                            bool ex = false;
                            for (int ii = 0; ii < funcs[i].FuncsIntoIndicies.Count; ii++)
                            {
                                if (funcs[i].FuncsIntoIndicies[ii] == k) { ex = true; break; }
                            }
                            if (!ex) { funcs[i].FuncsIntoIndicies.Add(k); funcs[i].FuncsInto.Add(funcs[k].Name.Trim()); }
                        }
                    }
                }
            }
            return funcs;
        }

        #region n
        //static void BuildTrees(List<FunctionInfo> vcs, List<FunctionInfo> lcs)
        //{
        //    //List<ClassInfo> my_funcs = ParseClasses("c\\funcs.txt");
        //    //Console.WriteLine($"{my_funcs.Count}");
        //    //for (int i = 0; i < lcs.Count; i++)
        //    //{
        //    //    for (int j = 0; j < my_funcs.Count; j++)
        //    //    {
        //    //        for (int k = 0; k < my_funcs[j].Methods.Count; k++)
        //    //        {
        //    //            if (lcs[i].IsFunctionEmpty && lcs[i].Name == my_funcs[j].Methods[k])
        //    //            {
        //    //                Console.WriteLine(lcs[i].Name);
        //    //            }
        //    //        }
        //    //    }
        //    //}
        //    //SaveClasses("c\\save", my_funcs);

        //    for (int i = 0; i < vcs.Count; i++)
        //    {
        //        //if (vcs[i].Name.Contains("sub_1034C8")) { Console.WriteLine($"sub_1034C8 {i}"); } // 38

        //        //if (vcs[i].Name.Contains("sub_38E9F8")) { Console.WriteLine($"sub_38E9F8 {i}"); } // 6431
        //        //if (vcs[i].Name.Contains("sub_38E928")) { Console.WriteLine($"sub_38E928 {i}"); } // 6430
        //        //if (vcs[i].Name.Contains("sub_103818")) { Console.WriteLine($"sub_103818 {i}"); } // 41
        //        //if (vcs[i].Name.Contains("sub_103650")) { Console.WriteLine($"sub_103650 {i}"); } // 39
        //    }

        //    for (int i = 0; i < vcs.Count; i++)
        //    {
        //        Console.WriteLine($"{i}");
        //        for (int j = 0; j < vcs[i].CodeLines.Count; j++)
        //        {
        //            if (j == 0) { continue; } // func header
        //            for (int k = 0; k < vcs.Count; k++)
        //            {
        //                if (Parser.RemoveComment(vcs[i].CodeLines[j].Trim()).Contains(vcs[k].Name.Trim()))
        //                {
        //                    bool ex = false;
        //                    for (int ii = 0; ii < vcs[i].FuncsIntoIndicies.Count; ii++)
        //                    {
        //                        if (vcs[i].FuncsIntoIndicies[ii] == k) { ex = true; break; }
        //                    }
        //                    if (!ex) { vcs[i].FuncsIntoIndicies.Add(k); vcs[i].FuncsInto.Add(vcs[k].Name.Trim()); }
        //                }
        //            }
        //        }
        //    }
        //    SaveToFile()
        //        Console.WriteLine("parsed");

        //}
        #endregion



        static void IsPlayerStuffCheck(List<FunctionInfo> fvcs, List<FunctionInfo> flcs)
        {
            #region d
            //// Пути к файлам
            //string pathLcs = "re\\lcs_ScriptCommands.h";
            //string pathVcs = "re\\MAZAHAKA_ScriptCommands.h";

            //// Читаем все строки
            //var linesLcs = File.ReadAllLines(pathLcs);
            //var linesVcs = File.ReadAllLines(pathVcs);

            //// Вспомогательная функция: из строки "  COMMAND_FOO_BAR, // comment" 
            //// извлечь "COMMAND_FOO_BAR"
            //string ExtractCmd(string line)
            //{
            //    // Убираем всё после //
            //    var idx = line.IndexOf("//");
            //    var code = idx >= 0 ? line.Substring(0, idx) : line;
            //    code = code.Trim();
            //    if (!code.EndsWith(",")) return null;
            //    // берём до запятой
            //    return code.Substring(0, code.Length - 1).Trim();
            //}

            //// Собираем команды из LCS в HashSet
            //var cmdsLcs = new HashSet<string>();
            //foreach (var line in linesLcs)
            //{
            //    var cmd = ExtractCmd(line);
            //    if (!string.IsNullOrEmpty(cmd))
            //        cmdsLcs.Add(cmd);
            //}

            //// Собираем команды из VCS в словарь: команда → индекс строки
            //var cmdsVcs = new Dictionary<string, int>();
            //for (int i = 0; i < linesVcs.Length; i++)
            //{
            //    var cmd = ExtractCmd(linesVcs[i]);
            //    if (!string.IsNullOrEmpty(cmd) && !cmdsVcs.ContainsKey(cmd))
            //        cmdsVcs[cmd] = i;  // i — это индекс строки в массиве linesVcs
            //}

            //// Собираем результат: все CHAR-команды, у которых есть аналог PLAYER в LCS и которые есть в VCS
            //var result = cmdsLcs
            //    .Where(c => c.Contains("_CHAR_"))
            //    .Where(charCmd => {
            //        var playerCmd = charCmd.Replace("_CHAR_", "_PLAYER_");
            //        return cmdsLcs.Contains(playerCmd) && cmdsVcs.ContainsKey(charCmd);
            //    })
            //    .OrderBy(c => cmdsVcs[c])  // можно сортировать по порядку появления в VCS
            //    .ToList();

            //// Выводим: имя команды + её индекс в VCS
            ////Console.WriteLine("Найденные _CHAR_-команды (с индексом строки в VCS):");
            //Console.WriteLine();
            //foreach (var cmd in result)
            //{
            //    int idx = cmdsVcs[cmd];
            //    //Console.WriteLine($"{idx}: {cmd}");
            //    //Console.WriteLine($"{cmd}");
            //    Console.WriteLine($"{idx}");
            //}

            ////// Выводим
            ////Console.WriteLine("Найденные _CHAR_-команды с соответствующими _PLAYER_-версиями, присутствующие в VCS:");
            ////foreach (var cmd in result)
            ////    Console.WriteLine(cmd);

            //// При желании можно положить в fvcs:
            //// foreach (var cmd in result)
            ////     fvcs.Add(new FunctionInfo { Name = cmd, /* … */ });
            #endregion

            string pops = "bin\\vcsiplayer.txt";
            int[] ops = File.ReadAllLines(pops).Where(x => x.Trim() != "").Select(x => int.Parse(x)).ToArray();
            foreach (int op in ops)
            {
                FunctionInfo f = fvcs.Where(x => x.Name.Contains("CRunningScript::ProcessCommand_") && x.Name.Contains($"_{op}_")).FirstOrDefault();
                Console.WriteLine($"{op} " + f.Name);
            }


        }


        class mi_node
        {
            public int index; // номер в исходном struct
            public string orig_struct_member_str; // full str   (int16 member)
            public string orig_def_str; // full str  MI_SOMEDEF    gpModelIndices->member
            public string orig_x_str; // full str  "mem"  MI_SOMEDEF   // "mem" is modelname

            public string defname; // MI_TESTRAMP1
            public string membername; // TESTRAMP1
            public string modelname; // Testramp1
            public string orig_ida_str;
            public bool is_in_ida;
            public int ida_index; // if 1 norm, 2 skip, 3 norm то считать без скипов, тоесть 3й будет 2
            public int ida_mi; // 0000005C MI_932_dk_camjonesdoor:.half ?    mi 932, modelname dk_camjonesdoor
        }
        static void tracemi()
        {
            List<mi_node> mi = new List<mi_node>();

            // коменты не удалять отсюда
            string[] defs = File.ReadAllLines("mi\\def.txt"); // #define MI_TRAFFICLIGHT01 gpModelIndices->TRAFFICLIGHT01
            string[] stru = File.ReadAllLines("mi\\stru.txt"); //     int16 TRAFFICLIGHT01;
            string[] x = File.ReadAllLines("mi\\x.txt"); //     X("trafficlight1", MI_TRAFFICLIGHTS) /* BUG: second time */ \
            string[] ida = File.ReadAllLines("mi\\ida.txt"); // 000000D6 MI_559_veg_palmkbb11:.half ?

            Console.WriteLine($"Загружено: defs={defs.Length}, stru={stru.Length}, x={x.Length}, ida={ida.Length}\n");
            // ida 
            // 0000005C MI_932_dk_camjonesdoor:.half ?   // mi 932, modelname dk_camjonesdoor
            // 0000006C MI_MINUS_N54:   .half ?      // skip  _MINUS_N    unknown
            // 000000D0 MI_524_DUPL_lamppost1:.half ? // skip _DUPL_      already exists

            // 2) Словарь: membername → (defname, orig_def_str)
            var dictDefByMember = new Dictionary<string, (string defname, string origDef)>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawLine in defs)
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("#define "))
                    continue;

                // defname - всё между "#define " (0..7) и первым пробелом после
                int posAfterDefine = 8;
                int spaceAfterDefname = line.IndexOf(' ', posAfterDefine);
                if (spaceAfterDefname < 0)
                    continue;
                string defname = line.Substring(posAfterDefine, spaceAfterDefname - posAfterDefine).Trim();

                // ищем "gpModelIndices->"
                int arrowPos = line.IndexOf("gpModelIndices->", spaceAfterDefname, StringComparison.Ordinal);
                if (arrowPos < 0)
                    continue;

                int memberStart = arrowPos + "gpModelIndices->".Length;
                int memberEnd = line.IndexOfAny(new char[] { ' ', '\t' }, memberStart);
                if (memberEnd < 0)
                    memberEnd = line.Length;
                string membername = line.Substring(memberStart, memberEnd - memberStart).Trim();
                if (string.IsNullOrEmpty(membername))
                    continue;

                if (!dictDefByMember.ContainsKey(membername))
                    dictDefByMember[membername] = (defname, rawLine);
            }

            // 3) Словарь: defname → (modelname, orig_x_str)
            var dictXByDef = new Dictionary<string, (string modelname, string origX)>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawLine in x)
            {
                string line = rawLine.Trim();
                int xPos = line.IndexOf("X(", StringComparison.Ordinal);
                if (xPos < 0)
                    continue;

                // ищем modelname между первой и второй кавычкой после "X("
                int quote1 = line.IndexOf('"', xPos + 2);
                if (quote1 < 0)
                    continue;
                int quote2 = line.IndexOf('"', quote1 + 1);
                if (quote2 < 0)
                    continue;
                string modelname = line.Substring(quote1 + 1, quote2 - quote1 - 1);

                // после quote2 ищем запятую
                int commaPos = line.IndexOf(',', quote2 + 1);
                if (commaPos < 0)
                    continue;

                int posAfterComma = commaPos + 1;
                while (posAfterComma < line.Length && Char.IsWhiteSpace(line[posAfterComma]))
                    posAfterComma++;

                // теперь вычленяем defname из символов [A-Za-z0-9_]
                int defEnd = posAfterComma;
                while (defEnd < line.Length)
                {
                    char c = line[defEnd];
                    if (!(Char.IsLetterOrDigit(c) || c == '_'))
                        break;
                    defEnd++;
                }
                if (defEnd <= posAfterComma)
                    continue;

                string defname = line.Substring(posAfterComma, defEnd - posAfterComma);
                if (!dictXByDef.ContainsKey(defname))
                    dictXByDef[defname] = (modelname, rawLine);
            }

            // 4) Словарь: lista всех «ненулевых» (non-skip) лейблов ida: label → (orig_ida_str, порядковый номер)
            //    Считаем только те, у которых label не содержит "_MINUS_" или "_DUPL_".
            //    label = всё до двоеточия после первого пробельного разделителя.
            var dictIdaLabels = new Dictionary<string, (string origIda, int order)>(StringComparer.OrdinalIgnoreCase);
            int currentIdaCounter = 0;
            foreach (string rawLine in ida)
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line))
                    continue;

                // разбиваем по пробелам на части
                string[] parts = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2)
                    continue;

                // parts[1] может быть "MI_XXX_modelname:…"
                string labelWithColon = parts[1];
                int colonPos = labelWithColon.IndexOf(':');
                string label = (colonPos >= 0) ? labelWithColon.Substring(0, colonPos) : labelWithColon;

                if (label.Contains("_MINUS_") || label.Contains("_DUPL_"))
                    continue;

                currentIdaCounter++;
                if (!dictIdaLabels.ContainsKey(label))
                    dictIdaLabels[label] = (rawLine, currentIdaCounter);
            }

            // 5) Проходим по каждой строке stru.txt и заполняем mi_node
            int realIndex = 0;
            foreach (string rawLine in stru)
            {
                string trimmed = rawLine.Trim();
                if (string.IsNullOrEmpty(trimmed) || !trimmed.StartsWith("int16 "))
                    continue;

                mi_node node = new mi_node
                {
                    index = realIndex++,
                    orig_struct_member_str = rawLine,
                    orig_def_str = "",
                    orig_x_str = "",
                    orig_ida_str = "",
                    defname = "",
                    membername = "",
                    modelname = "",
                    is_in_ida = false,
                    ida_index = 0
                };

                // 5.1) вырезаем membername: между "int16 " и первым ';'
                int startMember = 6; // длина "int16 "
                int semicolonPos = trimmed.IndexOf(';', startMember);
                if (semicolonPos < 0)
                    semicolonPos = trimmed.Length;
                node.membername = trimmed.Substring(startMember, semicolonPos - startMember).Trim();

                // 5.2) По membername ищем в dictDefByMember
                if (dictDefByMember.TryGetValue(node.membername, out var defInfo))
                {
                    node.defname = defInfo.defname;
                    node.orig_def_str = defInfo.origDef;
                }

                // 5.3) По defname ищем в dictXByDef, чтобы получить modelname
                if (!string.IsNullOrEmpty(node.defname) && dictXByDef.TryGetValue(node.defname, out var xInfo))
                {
                    node.modelname = xInfo.modelname;
                    node.orig_x_str = xInfo.origX;
                }

                // 5.4) Ищем в dictIdaLabels: любая запись, чей лейбл заканчивается на "_" + modelname (без учёта регистра)
                if (!string.IsNullOrEmpty(node.modelname))
                {
                    foreach (var kvp in dictIdaLabels)
                    {
                        string label = kvp.Key;
                        // Сравниваем с учётом регистра: если label.EndsWith("_" + modelname, игнорируя регистр)
                        if (label.EndsWith("_" + node.modelname, StringComparison.OrdinalIgnoreCase))
                        {
                            node.orig_ida_str = kvp.Value.origIda;
                            node.is_in_ida = true;
                            node.ida_index = kvp.Value.order;
                            break;
                        }
                    }
                }

                mi.Add(node);
            }

            //// 6) Выводим результат
            //Console.WriteLine("Содержимое mi:");
            //foreach (var n in mi)
            //{
            //    Console.WriteLine(
            //        $"index={n.index}, membername='{n.membername}', defname='{n.defname}', " +
            //        $"modelname='{n.modelname}', is_in_ida={n.is_in_ida}, ida_index={n.ida_index}"
            //    );
            //    if (!string.IsNullOrEmpty(n.orig_ida_str))
            //    {
            //        Console.WriteLine($"    orig_ida_str: {n.orig_ida_str}");
            //    }
            //}


            Console.WriteLine("=== Записи, найденные в ida (is_in_ida == true), отсортированные по ida_index ===");
            foreach (var node in mi
                .Where(n => n.is_in_ida)
                .OrderBy(n => n.ida_index))
            {
                // Выводим исходную строку struct (без лишних пробелов справа) и номер в ida
                Console.WriteLine($"{node.orig_struct_member_str.TrimEnd()}    // ida_index={node.ida_index}");
            }

            Console.WriteLine("\n=== Остальные записи (is_in_ida == false), в порядке исходного index ===");
            foreach (var node in mi
                .Where(n => !n.is_in_ida)
                .OrderBy(n => n.index))
            {
                Console.WriteLine(node.orig_struct_member_str.TrimEnd());
            }


        }


        //static bool IsExistsSubstr(List<string> rows, string search) // move func upper
        //{
        //    if (search.Trim() == "")
        //        return false;

        //    foreach (string s in rows)
        //    {
        //        if (s.ToLower().Contains(search.ToLower()))
        //            return true;
        //    }
        //    return false;
        //}
        static void test1()
        {
            // vcsmi.txt
            // gotovie.txt
            List<string> mi = File.ReadAllLines("bin\\vcsmi.txt").ToList();
            List<string> gr = File.ReadAllLines("bin\\gotovie.txt").ToList();
            List<string> test2 = File.ReadAllLines("bin\\test2.txt").ToList();

            // sfx
            //List<string> sfxs = File.ReadAllLines(".\\c\\sfx.h").ToList();
            List<string> ps2sfxs = File.ReadAllLines(".\\c\\sfx.h")
           // 1) удаляем строки, которые после TrimStart() начинаются с "//"
           .Select(line => line.TrimStart())
           .Where(line => !line.StartsWith("//"))
           // 2) убираем inline‑комментарии: всё после "//"
           .Select(line =>
           {
               int _idx = line.IndexOf("//", StringComparison.Ordinal);
               return _idx >= 0 ? line.Substring(0, _idx) : line;
           })
           // 3) разбиваем по запятой и берём левую часть
           .Select(line =>
           {
               var parts = line.Split(new[] { ',' }, StringSplitOptions.None);
               return parts.Length > 0 ? parts[0].Trim() : string.Empty;
           })
           // 4) отбрасываем пустые
           .Where(token => !string.IsNullOrEmpty(token)).ToList();
            Console.WriteLine($"ps2sfxs: {ps2sfxs.Count}");
            Console.WriteLine($"mi: {mi.Count}");
            Console.WriteLine($"gr: {gr.Count}");
            Console.WriteLine($"test2: {test2.Count}");


            //foreach (var m in mi)
            //{
            //    if(!IsExistsSubstr(gr, m))
            //    {
            //        Console.WriteLine($"case {m}:");
            //    }
            //}

            //foreach (var item in test2)
            //{
            //    if (item.Contains("case "))
            //    {

            //        bool find = false;
            //        foreach (var mgr in gr)
            //        {
            //            if (mgr.Contains("case "))
            //            {
            //                if (mgr.Trim() == item.Trim())
            //                    find = true;
            //            }
            //        }
            //        if(!find)
            //         Console.WriteLine(item);
            //    }
            //}



            //List<(int, string)> res = new List<(int, string)>();
            //foreach (var g in gr)
            //    res.Add((0, g));

            //for (int i = 0; i < gr.Count; i++)
            //{
            //    for (int j = 0; j < mi.Count; j++)
            //    {
            //        if (gr[i].Contains(mi[j]))
            //            res[i].Item1++;
            //    }
            //}

            //var grSet = new HashSet<string>(gr);
            //// Собираем все элементы mi, которых нет в gr
            //var unusedMi = mi
            //    .Where(item => !grSet.Contains(item))
            //    .ToList();

            //Console.WriteLine($"\nНайдено mi, не использующихся в gr: {unusedMi.Count}");
            //foreach (var missing in unusedMi)
            //{
            //    Console.WriteLine(missing);
            //}


        }

        static void test2()
        {
            // sfx
            //List<string> sfxs = File.ReadAllLines(".\\c\\sfx.h").ToList();
            List<string> ps2sfxs = File.ReadAllLines(".\\c\\sfx.h")
           // 1) удаляем строки, которые после TrimStart() начинаются с "//"
           .Select(line => line.TrimStart())
           .Where(line => !line.StartsWith("//"))
           // 2) убираем inline‑комментарии: всё после "//"
           .Select(line =>
           {
               int _idx = line.IndexOf("//", StringComparison.Ordinal);
               return _idx >= 0 ? line.Substring(0, _idx) : line;
           })
           // 3) разбиваем по запятой и берём левую часть
           .Select(line =>
           {
               var parts = line.Split(new[] { ',' }, StringSplitOptions.None);
               return parts.Length > 0 ? parts[0].Trim() : string.Empty;
           })
           // 4) отбрасываем пустые
           .Where(token => !string.IsNullOrEmpty(token)).ToList();


        }

        class match
        {
            public string tfname;
            public string vfname;
            public string tfcode;
            public string vfcode;
            public string val;
            public match(string _tfname, string _vfname, string _tfcode, string _vfcode, string _val)
            {
                tfname = _tfname;
                vfname = _vfname;
                tfcode = _tfcode;
                vfcode = _vfcode;
                val = _val;
            }
        }

        //Разбор операций кода
        //Преобразование точки матрицей(vfpu_transform_point)
        //Инструкция: vtfm3.t(Vector Transform Matrix 3 Triple).
        //Суть: Умножение трехмерного вектора(точки) на матрицу трансформации 3 × 3 (обычно используется для трансформации координат в 3D-графике) с последующим сложением(vadd.t). [1] (https://www.pyra-handheld.com/boards/threads/pandora-psp.58420/latest), [2] (https://gist.github.com/sajattack/55c3f1f9b19f312d16fc3d54c03b7111)

        //Скалярное произведение (vfpu_dot_product)
        //Инструкция: vdot.t (Vector Dot Product Triple).
        //Суть: Вычисление скалярного произведения двух трехмерных векторов. Результат переносится обратно в регистры CPU через mfv (Move From VFPU). [1] (http://hlide.free.fr/)
        //Сложение векторов (vfpu_vector_add)
        //Инструкция: vadd.t (Vector Add Triple).
        //Суть: Покомпонентное сложение двух трехмерных векторов. [1] (https://hitmen.c02.at/files/yapspd/psp_doc/chap4.html)

        //Вычитание векторов (vfpu_vector_sub)
        //Инструкция: vsub.t (Vector Subtract Triple).
        //Суть: Покомпонентное вычитание одного трехмерного вектора из другого. [1] (https://inbox.sourceware.org/gcc-patches/20260120233217.1363827-8-david@davidgf.net/T/)

        //Масштабирование (умножение на скаляр) (vfpu_vector_scale)
        //Инструкция: vscl.t (Vector Scale Triple).
        //Суть: Умножение всех компонентов трехмерного вектора на один скаляр (значение скаляра предварительно передается через mtv). [1] (https://gist.github.com/sajattack/55c3f1f9b19f312d16fc3d54c03b7111)

        //Масштабирование с делением (vfpu_vector_scale_inv)
        //Инструкции: vrcp.s (Vector Reciprocal Single) + vscl.t.
        //Суть: Деление вектора на скаляр. Так как деление в VFPU медленное, оно оптимизируется: сначала вычисляется обратная величина скаляра (1/x с помощью vrcp.s), а затем вектор умножается на этот результат через vscl.t. [1] (https://gist.github.com/sajattack/55c3f1f9b19f312d16fc3d54c03b7111)

        //Копирование вектора (vfpu_vector_copy)
        //Инструкции: lv.q и sv.q.
        //Суть: Базовое чтение вектора из одной ячейки памяти и прямая запись в другую без математических преобразований.

        //Векторное произведение (vfpu_cross_product)
        //Инструкция: vcrsp.t (Vector Cross Product Triple).
        //Суть: Вычисление классического векторного произведения двух векторов в трехмерном пространстве (результатом является перпендикулярный им вектор). [1] (https://gist.github.com/sajattack/55c3f1f9b19f312d16fc3d54c03b7111)

        //Нормализация с защитой от нуля (vfpu_normalize)
        //Инструкции: vidt.q (Vector Identity), vdot.t, vcmp.s (Vector Compare), vrsq.s (Vector Reciprocal Square Root), vscl.t, vcmovt.t (Vector Conditional Move If True).
        //Суть: Приведение вектора к единичной длине. Защита от нуля проверяет, не равна ли длина вектора нулю (с помощью сравнения vcmp.s), чтобы избежать критической ошибки деления на ноль. Если длина нулевая, условное перемещение vcmovt.t подставляет дефолтный или безопасный вектор (например, единичный vidt.q). [1] (https://github.com/jdek/jim-psp/blob/master/binutils-psp/opcodes/mips-opc.c), [2] (http://hlide.free.fr/)

        //Длина вектора (vfpu_magnitude)
        //Инструкции: vdot.t + vsqrt.s (Vector Square Root Single).
        //Суть: Нахождение геометрической длины вектора по формуле 

        //Сначала вектор умножается сам на себя (vdot.t), получая сумму квадратов, а затем извлекается квадратный корень.

        //Квадрат длины вектора (vfpu_magnitude_sqr)
        //Инструкция: vdot.t.
        //Суть: Вычисление значения x + y + z. Более быстрая операция, так как пропускается тяжелый для процессора шаг извлечения корня (vsqrt.s).

        private static Dictionary<string, int> _nameCount = new Dictionary<string, int>();

        // вызывать только на функции с только __asm
        static void OnASMFInfo(FunctionInfo f) // сдампил все asm_ дал дипсику на сортировку выборку и генерацию имён, затем написал паттерны для них я отладил
        { // ps: регистры могут быть разные S700 S010, с return и без
            //[0] {
            //[1] __asm
            //[2] {
            const int startIdx = 3; // vfpubaseoffset
            if (f.CodeLines.Count <= startIdx)
                return;

            // Извлечение мнемоник всех инструкций внутри asm-блока
            var mnemonics = new List<string>();
            int lastCut = (f.CodeLines.Count > 3 && f.CodeLines[f.CodeLines.Count-1].Trim() == "}" && f.CodeLines[f.CodeLines.Count-2].Trim().Contains("return ")) ? 3 : 2;
            for (int i = startIdx; i < f.CodeLines.Count - lastCut; i++)
            {
                string line = f.CodeLines[i].Trim();
                if (string.IsNullOrEmpty(line))
                    continue;
                string[] parts = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0)
                    mnemonics.Add(parts[0]); // берём первое слово – мнемонику
            }

            // Правила (пункты 1–11) с новыми именами и точными последовательностями мнемоник
            // vdot.p pair(2d)   vdot.t triple(3d)
            var patterns = new Dictionary<string, List<string>>()
            {
                // 1. Преобразование точки матрицей (vtfm3 + vadd)
                { "vfpu_transform_point", new List<string> { "lv.q", "lv.q", "lv.q", "lv.q", "lv.q", "vtfm3.t", "vadd.t", "sv.q" } },
                // 2. Скалярное произведение
                { "vfpu_dot_product", new List<string> { "lv.q", "lv.q", "vdot.t", "mfv" } },
                // 3. Сложение векторов
                { "vfpu_vector_add", new List<string> { "lv.q", "lv.q", "vadd.t", "sv.q" } },
                // 4. Вычитание векторов
                { "vfpu_vector_sub", new List<string> { "lv.q", "lv.q", "vsub.t", "sv.q" } },
                // 5. Масштабирование (умножение на скаляр)
                { "vfpu_vector_scale", new List<string> { "mtv", "lv.q", "vscl.t", "sv.q" } },
                // 6. Масштабирование с делением (vrcp)
                { "vfpu_vector_scale_inv", new List<string> { "mtv", "vrcp.s", "lv.q", "vscl.t", "sv.q" } },
                // 7. Копирование вектора
                { "vfpu_vector_copy", new List<string> { "lv.q", "sv.q" } },
                // 8. Векторное произведение
                { "vfpu_cross_product", new List<string> { "lv.q", "lv.q", "vcrsp.t", "sv.q" } },
                // 9. Нормализация с защитой от нуля
                { "vfpu_normalize", new List<string> { "lv.q", "vidt.q", "vdot.t", "vcmp.s", "vrsq.s", "vscl.t", "vcmovt.t", "sv.q" } },
                // 10. Длина вектора (sqrt(dot))
                { "vfpu_magnitude", new List<string> { "lv.q", "vdot.t", "vsqrt.s", "mfv" } },
                // 11. Квадрат длины вектора (dot без sqrt)
                { "vfpu_magnitude_sqr", new List<string> { "lv.q", "vdot.t", "mfv" } },

                // 12. Преобразование точки матрицей без смещения (только поворот/масштаб)
                { "vfpu_transform_point_no_translate", new List<string> { "lv.q", "lv.q", "lv.q", "lv.q", "vtfm3.t", "sv.q" } },
                // 13. Отрицание вектора
                { "vfpu_negate_vector", new List<string> { "lv.q", "vneg.t", "sv.q" } },
                // 14. Синус
                { "vfpu_sin", new List<string> { "mtv", "vcst.s", "vmul.s", "vsin.s", "mfv" } },
                // 15. Косинус
                { "vfpu_cos", new List<string> { "mtv", "vcst.s", "vmul.s", "vcos.s", "mfv" } },
                // 16. Арксинус
                { "vfpu_asin", new List<string> { "mtv", "vcst.s", "vsat1.s", "vasin.s", "vmul.s", "mfv" } },
                // 17. Арккосинус (дополнение до PI/2)
                { "vfpu_acos", new List<string> { "mtv", "vcst.s", "vsat1.s", "vasin.s", "vmul.s", "vsub.s", "mfv" } },
                // 18. Возведение в степень (pow)
                { "vfpu_pow", new List<string> { "mtv", "mtv", "vlog2.s", "vmul.s", "vexp2.s", "mfv" } },
                // 19. Длина 2D-вектора (sqrt(dot.p))
                { "vfpu_magnitude_2d", new List<string> { "lv.q", "vdot.p", "vsqrt.s", "mfv" } },
                // 20. Квадрат длины 2D-вектора (dot.p без sqrt) – добавлен на всякий случай
                { "vfpu_magnitude_sqr_2d", new List<string> { "lv.q", "vdot.p", "mfv" } },
            };

            string newName = null;
            foreach (var kv in patterns)
            {
                // Точное сравнение последовательности мнемоник
                if (mnemonics.Count == kv.Value.Count && mnemonics.SequenceEqual(kv.Value))
                {
                    newName = kv.Key;
                    break;
                }
            }

            if (newName != null)
            {
                //string output = $"{f.Name} {f.IdaAddress} {newName}";
                //File.AppendAllText("rename.txt", output + Environment.NewLine);

                int count;
                if (_nameCount.ContainsKey(newName))
                {
                    count = _nameCount[newName] + 1;
                    _nameCount[newName] = count;
                }
                else
                {
                    count = 0;
                    _nameCount[newName] = 0;
                }

                string uniqueName = $"_ZN{newName.Length}{newName}Ei{(count > 0 ? $"_{count}" : "")}"; // add mang
                string idcLine = $"set_name(0x{f.IdaAddress:X}, \"{uniqueName}\", SN_AUTO);";
                File.AppendAllText("rename.txt", idcLine + Environment.NewLine);
            }
        }

        static int CharCount(string s, char ch)
        {
            int i = 0;
            foreach (char c in s) {
                if (c == ch) ++i;
            }
            return i;
        }
        static int CharCount(List<string> s, char ch)
        {
            int i = 0;
            foreach (var c in s)
            {
                i += CharCount(c, ch);
            }
            return i;
        }

        static void Main()
        {
            // 0xA0 ?
            bool fast = true;
            Console.WriteLine("Parse vcs.c");
            List<FunctionInfo> vcsfunctions = new List<FunctionInfo>();
            Parser VcsParser = new Parser("c\\vcs", "c\\vcs.c", 0x1000, 0x00100000); // !!!!!!!!!
            vcsfunctions = VcsParser.Parse(fast); // !!!!!!!!!
            //if (!File.Exists("c\\vcsparse.json"))
            //{
            //    Parser VcsParser = new Parser("c\\vcs", "c\\vcs.c", 0x1000, 0x00100000);
            //    vcsfunctions = VcsParser.Parse(fast);
            //    vcsfunctions = BuildTree(vcsfunctions);
            //    Parser.SaveToFile(vcsfunctions, "c\\vcsparse.json");
            //}
            //else { vcsfunctions = Parser.LoadFromFile("c\\vcsparse.json"); }
            Console.WriteLine($"vcs: {vcsfunctions.Count}");
            Console.WriteLine("Parse lcsapk.c");
            List<FunctionInfo> lcsfunctions = new List<FunctionInfo>();
            Parser LcsParser = new Parser("", "c\\lcsapk.c", 0x0, 0x00100000, true); //!!!!!!!
            lcsfunctions = LcsParser.Parse(fast); // !!!!!!!!!!!!!
            //if (!File.Exists("c\\lcsparse.json"))
            //{
            //    Parser LcsParser = new Parser("", "c\\lcsapk.c", 0x0, 0x00100000, true);
            //    lcsfunctions = LcsParser.Parse(fast);
            //    lcsfunctions = BuildTree(lcsfunctions);
            //    Parser.SaveToFile(lcsfunctions, "c\\lcsparse.json");
            //}
            //else { lcsfunctions = Parser.LoadFromFile("c\\lcsparse.json"); }
            Console.WriteLine($"lcs: {lcsfunctions.Count}");
            Console.WriteLine("Parse 3.c");
            List<FunctionInfo> threefunctions = new List<FunctionInfo>();
            if (!File.Exists("c\\3parse.json"))
            {
                Parser ThreeParser = new Parser("c\\3", "c\\3.c", 0x80, 0x00100000);
                threefunctions = ThreeParser.Parse(fast);
                threefunctions = BuildTree(threefunctions);
                Parser.SaveToFile(threefunctions, "c\\3parse.json");
            }
            else { threefunctions = Parser.LoadFromFile("c\\3parse.json"); }
            Console.WriteLine($"3: {threefunctions.Count}");


            List<FunctionInfo> lcspspfunctions = new List<FunctionInfo>();
            {
                Console.WriteLine("Parse lcspsp.c");
                Parser LcsPspParser = new Parser("", "c\\lcspsp.c", 0x0, 0x00100000, true); //!!!!!!!
                lcspspfunctions = LcsPspParser.Parse(true); // !!!!!!!!!
                Console.WriteLine($"lcspsp: {lcspspfunctions.Count}");
            }
            List<FunctionInfo> vcspspfunctions = new List<FunctionInfo>();
            {
                Console.WriteLine("Parse vcspsp.c");
                Parser VcsPspParser = new Parser("", "c\\vcspsp.c", 0x0, 0x00100000, true); //!!!!!!!
                vcspspfunctions = VcsPspParser.Parse(true); // !!!!!!!!!
                Console.WriteLine($"vcspsp: {vcspspfunctions.Count}");
            }
            List<FunctionInfo> revcsfunctions = new List<FunctionInfo>();
            {
                Console.WriteLine("Parse revcs.c");
                Parser ReVcsParser = new Parser("", "c\\revcs.c", 0x0, 0x00100000, true); //!!!!!!!
                revcsfunctions = ReVcsParser.Parse(true); // !!!!!!!!!
                Console.WriteLine($"revcs: {revcsfunctions.Count}");
            }
            List<FunctionInfo> test2 = new List<FunctionInfo>();
            {
                Console.WriteLine("Parse test2.c");
                Parser test2Parser = new Parser("", "c\\test2.c", 0x0, 0x00100000, true); //!!!!!!!
                test2 = test2Parser.Parse(true); // !!!!!!!!!
                Console.WriteLine($"test2: {test2.Count}");
            }

            // 8 поиск функций по имени класа // +-
            // 9 собрать список функций (кодом)
            // 10 поиск блока псевдокода
            // 11 крутой посикк подскроки/маски в псевдокоде
            int mode = 2;
            //mode = 10;
            //mode = 1;
            mode = 11; // крутой поисковик    12 mask finder
            //mode = 8; // search funnctions
            /////////mode = 9;// играться с list ---------------------
            mode = 13; // cmp psp ps2 vcs like mode 8
            //mode = 14;// revcs смотрю чё не сделал ещё
            mode = 9;// играться с list ---------------------

            if (mode == 0) // asm
            {
                ProduseAsm1(vcsfunctions, threefunctions);
                //VcsParser.Dump(vcsfunctions);

            }
            else if (mode == 1) // script io test !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            {
                reSrcParseScrIO(vcsfunctions);
            }
            else if (mode == 2)
            {
                //audioTest(vcsfunctions); return;
                //test2(); return;
                //test1(); return;

                Console.WriteLine("0 - three | 1 - lcs | 2 - vcs | 3 - lcspsp | 4 - vcspsp"); // Чё вообще доступно
                //Console.WriteLine($"Выбран режим: {mode} (vcs)"); // Подтверждение выбора
                Console.Write("Выбери лист (0/1/2/3/4): "); // Ждём ввод
                string input = Console.ReadLine();
                List<FunctionInfo> selectedList;
                // Выбираем нужный лист на основе ввода
                switch (input)
                {
                    case "0":
                        selectedList = threefunctions;
                        Console.WriteLine("Выбран threefunctions");
                        break;
                    case "1":
                        selectedList = lcsfunctions;
                        Console.WriteLine("Выбран lcsfunctions");
                        break;
                    case "2":
                        selectedList = vcsfunctions;
                        Console.WriteLine("Выбран vcsfunctions");
                        break;
                    case "3":
                        selectedList = lcspspfunctions;
                        Console.WriteLine("Выбран lcspspfunctions");
                        break;
                    case "4":
                        selectedList = vcspspfunctions;
                        Console.WriteLine("Выбран vcspspfunctions");
                        break;
                    default:
                        Console.WriteLine("Неверный ввод, еблан. Используется vcsfunctions по умолчанию.");
                        selectedList = vcsfunctions; // Дефолтный выбор
                        break;
                }
                Console.Write("enter search str: ");
                string srch = Console.ReadLine().Trim();

                //List<match> m = new List<match>();
                //foreach (var f in threefunctions)
                //{
                //    foreach (string fs in f.CodeLines)
                //    {
                //        if (fs.Contains("MEMORY[0x1000")) // "  v4 = MEMORY[0x1000E000] & 1i64;"
                //        {
                //            Regex regex = new Regex(@"MEMORY\[0x([0-9A-Fa-f]+)\]");
                //            Match match = regex.Match(fs);
                //            if (match.Success)
                //            {
                //                string hexValue = match.Groups[1].Value;
                //                //int intValue = Convert.ToInt32(hexValue, 16);
                //                //Console.WriteLine($"{hexValue} {fs}");
                //                m.Add(new match(f.Name, "", fs.Trim(), "", hexValue));
                //            }
                //        }
                //    }
                //}
                //foreach (var mi in m)
                //{
                //    foreach (var f in vcsfunctions)
                //    {
                //        foreach (string fs in f.CodeLines)
                //        {
                //            if (fs.Contains("MEMORY[0x1000"))
                //            {
                //                Regex regex = new Regex(@"MEMORY\[0x([0-9A-Fa-f]+)\]");
                //                Match match2 = regex.Match(fs);
                //                if (match2.Success && match2.Groups[1].Value == mi.val)
                //                {
                //                    // как только нашли совпадение — записываем имя функции из vcs
                //                    // (если нужно несколько, можно делать += ", " + f.Name)
                //                    mi.vfname = f.Name;
                //                    mi.vfcode = fs.Trim();
                //                    // можно сразу выйти из inner-loop, если больше не надо искать
                //                    goto NextMatch;
                //                }
                //            }
                //        }
                //    }
                //    NextMatch:
                //    ;
                //}
                ////Console.WriteLine($"{"threeFunc",-30} {"vcsFunc",-30} {"hex",-10} Код");
                ////Console.WriteLine(new string('-', 80));
                //foreach (var mi in m)
                //{
                //    //Console.WriteLine($"{mi.tfname,-30} {mi.vfname,-30} {mi.val,-10} {mi.fcode}");
                //    Console.WriteLine($"{mi.tfname,-30} {mi.tfcode}");
                //    Console.WriteLine($"{mi.vfname,-30} {mi.vfcode}\n\n");
                //}
                //return;


                int total = 0;
                //foreach (var f in threefunctions)
                //foreach (var f in lcsfunctions)
                //foreach (var f in vcsfunctions)
                foreach (FunctionInfo f in selectedList) // thanks BYDLOCODE DEEPSEEK
                {
                    //if(f.Name == "CEventList::Shutdown") // lcs
                    //if (f.Name == "CTheZones::PostZoneCreation") // lcs
                    //if (f.Name == "MULTISTATE_MENU_ITEM_sub_2F0768") // vcs
                    //if (f.Name.Contains("CRunningScript::ProcessCommand_")) // vcs
                    {
                        //bool e = IsExistsSubstr(f.CodeLines, "= 32");
                        //bool e1 = IsExistsSubstr(f.CodeLines, "= 24");
                        //bool e2 = IsExistsSubstr(f.CodeLines, "= 16");
                        //bool e3 = IsExistsSubstr(f.CodeLines, "= 8");
                        //bool e4 = IsExistsSubstr(f.CodeLines, "= 4");
                        //if(e && e1 && e2 && e3 && e4)
                        //    Console.WriteLine($"{f.Name}");
                        //continue;

                        //Console.WriteLine(f.IsFunctionEmpty);
                        //foreach (string fs in f.FuncsInto)
                        foreach (string fs in f.CodeLines)
                        {
                            //if (!fs.Contains("health = ")) { continue; }
                            //if (!fs.Contains("m_fMaxHealth")) { continue; }
                            //if (fs.Contains("| 0x1000000;")
                            //    || fs.Contains("& 0x1000000;")
                            //    || fs.Contains("POOLFLAG_BUILDING")
                            //    || fs.Contains("| 0x800000;")
                            //    || fs.Contains("& 0x800000;")
                            //    || fs.Contains("POOLFLAG_EMPIRE")
                            //    )
                            //if (fs.Contains("16, 255"))
                            //if (fs.Contains("0x43"))
                            //if (fs.Contains(">> 60"))
                            //if (fs.Contains("(1i64, -2i64)"))
                            //if (fs.Contains("50000000")) // RW!!!
                            //if (fs.Contains("_$RA"))
                            //if (fs.Contains("FF0000FF0000000"))
                            //if (fs.Contains("0x31000118"))
                            if (fs.Contains(srch))
                            //if (false)
                            {
                                Console.WriteLine("\n" + f.Name + "\n\n" + fs.Trim() + "\n\n\n\n");
                            }

                            //// ps2 sdk
                            //if (fs.Contains("MEMORY[0x1000"))
                            //    //Console.WriteLine("\n" + f.Name + "\n\n" + fs.Trim() + "\n\n\n\n");
                            //    Console.WriteLine($"{fs} ({f.Name})");
                        }
                    }


                    //{
                    //    string[] skipWords = {
                    //    "CPed", "CVehicle", "CAutomobile", "CPlane", "CEntity",
                    //    "CPhysical", "CHeli", "CBmx", "CQuad", "CFakePlane",
                    //    "CBike", "CRunningScript", "CTheScripts", "alloc", "CPhone", "CGarage",
                    //    };
                    //    string fl = f.Name.ToLower();
                    //    // Проверяем, нужно ли пропустить эту функцию
                    //    bool shouldSkip = skipWords.Any(word =>
                    //                          string.Equals(word, f.Name, StringComparison.OrdinalIgnoreCase)) ||
                    //                      skipWords.Any(sub => fl.Contains(sub.ToLower()));


                    //    if (!shouldSkip)
                    //    {
                    //        File.AppendAllText("VCSDECOMP.TXT", f.Name);
                    //        File.AppendAllLines("VCSDECOMP.TXT", f.CodeLines);
                    //    }
                    //}


                    {
                        string[] empireHudAll =
                        {
                            //"empirehud",
                            "cpathfind",

                            // "_1104_", "_1107_", "_1108_", "_1109_", "_1110_", "_1111_", "_1112_", "_1113_",
                            //"_1114_", "_1115_", "_1116_", "_1117_", "_1163_", "_1164_",

                            //"CEmpireHud::DrawHudElement", "cempirehud_ProcessTextRectStuff_", " CEmpireHud::RenderHudNodeEleme",
                            //"empirehud_setresourcekey_andsomestuff_sub_", "cempirehud_somenewelement_sub_1052", "cempirehud_sub_1059B",
                            //"cempirehud_someclearname_sub_1", "cempirehud_foundinfo_sub_1061", "empirehud_sub_106250",
                            //"empirehud_sub_106298", "empirehud_sub_1062D0", "mpirehud_sub_106310", "empirehud_setCurrentPos_sub_106350",
                            //"cempirehud_sub_1063A0", "cempirehud_sub_106570", "empire_csprite2_sub_1065D0", "CEmpireHud::DrawIcon",
                            //"cempirehud_setsomeelement_iconsize_sub_106768"
                        };

                        string funcNameLower = f.Name.ToLower();
                        bool should = empireHudAll.Any(id => funcNameLower.Contains(id.ToLower()));
                        bool guess = IsExistsSubstr(f.CodeLines, "guess"); // in comments

                        should = f.Name.ToLower().Contains("cWorldStream::".ToLower());
                        bool shws = should;
                        should = f.Name.ToLower().Contains("cWorldStreamEx::".ToLower());
                        bool shwse = should;
                        should = f.Name.ToLower().Contains("cWorldGeom::".ToLower());
                        bool shwg = should;
                        should = f.Name.ToLower().Contains("cStringT".ToLower());
                        should = shws || shwse || shwg;
                        //should = f.Name.ToLower().Contains("cPedCommentsManager::Get".ToLower());
                        //should = f.Name.ToLower().Contains("cPedCommentsManager::GetGenericPedCommentSfx".ToLower());
                        //if (should && (/*f.Name.Contains("PedCommentsManager::GetPlayer") ||*/ f.Name.Contains("PedCommentsManager::GetGenericPedCommentSf")))
                        //    should = false;

                        //f.CodeLines.Insert(1, $"  gCallName = \"return m_PedComentsManager.{f.Name.Replace("cPedCommentsManager::", "")}(ped, sound);\";");
                        //f.CodeLines.Insert(2, $"  gCallName2 = \"{f.Name.Replace("cPedCommentsManager::", "")}\";");
                        //f.FuncHeader = f.FuncHeader.Replace("cPedCommentsManager *this, ", "");
                        should = false;
                        if (should)
                        {
                            string fname = "OUTPUT.TXT";
                            //fname = "OPCODES.TXT";

                            //File.AppendAllText(fname, $"int {f.Name}(args)\r\n");
                            //File.AppendAllText(fname, $"{f.FuncHeader}{(guess ? " // guessed" : "")}".Replace("__int64 __fastcall", "void"));
                            File.AppendAllText(fname, $"{f.FuncHeader}\r\n");
                            File.AppendAllLines(fname, f.CodeLines);
                            File.AppendAllText(fname, "\r\n");
                            ++total;
                        }
                    }

                    //foreach (var item in f.CodeLines)
                    //{
                    //    if(item.Contains("480.0"))
                    //        Console.WriteLine(f.Name);
                    //}

                }
                Console.WriteLine($"total: {total}");
                //BuildTrees(vcsfunctions, lcsfunctions);
            }
            else if (mode == 3) // isplayer
            {
                IsPlayerStuffCheck(vcsfunctions, lcsfunctions);
            }
            else if (mode == 4)
            {
                tracemi();
            }
            else if (mode == 5)
            {
                //List<string> possibleDebug = new List<string>();
                List<FunctionInfo> possibleDebug = new List<FunctionInfo>();
                foreach (FunctionInfo f in lcspspfunctions) // thanks BYDLOCODE DEEPSEEK
                {
                    //if(f.Name == "debug22")
                    //{
                    //    Console.WriteLine("sdfdsf");
                    //}
                    if (f.CodeLines.Count != 3)
                        continue;
                    if (!(f.CodeLines[0].Trim().StartsWith("{") && f.CodeLines[1].Trim().StartsWith("return 0;") && f.CodeLines[2].Trim().StartsWith("}")))
                        continue;
                    if (!(f.Name.StartsWith("sub_") || f.Name.StartsWith("nullsub_")))
                        continue;
                    //if (!(f.FuncHeader.Contains("const char *") && f.FuncHeader.Contains("...")))
                    //    continue;
                    //possibleDebug.Add(f.Name);
                    //Console.WriteLine(f.Name);
                    possibleDebug.Add(f);

                    //foreach (string fs in f.CodeLines)
                    //{
                    //    //if (fs.Contains(""))
                    //    //if (false)
                    //    {
                    //        Console.WriteLine("\n" + f.Name + "\n\n" + fs.Trim() + "\n\n\n\n");
                    //    }
                    //}
                }

                //foreach (FunctionInfo df in possibleDebug)
                //    Console.WriteLine($"{df.Name}");
                //return;

                //foreach (FunctionInfo f in lcspspfunctions)
                //{
                //    foreach (FunctionInfo df in possibleDebug)
                //    {
                //        bool iscalled = IsExistsSubstr(f.CodeLines, $"{df.Name}(\"");
                //        if(iscalled)
                //            Console.WriteLine(df.Name);
                //    }
                //}

                foreach (FunctionInfo df in possibleDebug)
                    Console.WriteLine(df.Name);
                Console.WriteLine("END!!\n\n\n\n");

                foreach (FunctionInfo df in possibleDebug)
                {
                    if (df.Name.Contains("sub_8973F5C"))
                    {
                        int t = 0;
                    }
                    else continue;

                    foreach (FunctionInfo f in lcspspfunctions)
                    {
                        if (f.Name.Contains("sub_8974230"))
                        {
                            int t = 0;
                        }
                        bool iscalled = IsExistsSubstr(f.CodeLines, $"{df.Name}(\"");
                        if (iscalled)
                        {
                            Console.WriteLine(df.Name);
                            break; // its df is log, prevent duplicate print same
                        }
                    }
                }

            }
            else if (mode == 6)
            {
                const int MI_FIRST_VEHICLE = 170;
                List<(int, string)> mi = new List<(int, string)>();
                List<string> rows = File.ReadAllLines("bin\\vcsmi2.txt").ToList();
                for (int i = 0; i < rows.Count; i++)
                    mi.Add((i, rows[i].Replace(" ", "").Replace(",", "")));

                //Console.WriteLine(mi[280].Item2);

                List<string> test3 = File.ReadAllLines("bin\\test3.txt").ToList();
                for (int i = MI_FIRST_VEHICLE; i < mi.Count; i++)
                {
                    string modelname = mi[i].Item2;
                    bool e = IsExistsSubstr(test3, modelname);
                    if (!e)
                    {
                        //Console.WriteLine(modelname);

                        string buff = "";
                        string name = modelname.Replace("MI_", "").ToLower();
                        if (IsExistsSubstr(test3, $"\"{name}\""))
                            Console.WriteLine($"ERROR!!!!!!!! exist {name}");
                        buff += $"lua_pushstring(L, \"{name}\");\r\n";
                        buff += $"lua_pushnumber(L, {modelname});\r\n";
                        buff += $"lua_settable(L, -3);";
                        buff = $"LUA_PUSH_CONSTANT(\"{name}\", {modelname});";
                        Console.WriteLine(buff);
                    }
                }

            }
            else if (mode == 7)
            {
                foreach (FunctionInfo f in vcspspfunctions) // thanks BYDLOCODE DEEPSEEK
                //foreach (FunctionInfo f in lcspspfunctions) // thanks BYDLOCODE DEEPSEEK
                {
                    if (f.Name.StartsWith("alloc_"))
                    {
                        bool pck = IsExistsSubstr(f.CodeLines, "\"");
                        if (pck)
                            Console.WriteLine($"{f.Name}");
                    }
                }

            }
            else if (mode == 8) // find non moved functions in vcs psp from vcs ps2
            {
                string classname = "CPlayerPed::";
                Console.Write("Enter class name: ");
                classname = Console.ReadLine();
                classname += "::";
                Console.WriteLine();

                var vcspspNames = new HashSet<string>(vcspspfunctions.Select(f => f.Name));
                foreach (FunctionInfo f in vcsfunctions)
                {
                    //if (!string.IsNullOrEmpty(classname) && !f.Name.StartsWith(classname))
                    if (!string.IsNullOrEmpty(classname) && !f.Name.ToLower().Contains(classname))
                        continue;

                    if (!vcspspNames.Contains(f.Name))
                        Console.WriteLine(f.Name);
                }

                List<(string, int)> vcsinfo = GetClassCounts(vcsfunctions);
                List<(string, int)> vcspspinfo = GetClassCounts(vcspspfunctions);
                //foreach (var item in vcsinfo)
                //Console.WriteLine($"{item.Item1} {item.Item2}");
            }
            else if (mode == 9) // дампер функций по фильтру
            {

                // sort for neyronka po 1mb
                if(false)
                {
                    // Сортировка функций по адресу в ELF (ElfAddress)
                    var sorted = vcspspfunctions.OrderBy(f => f.ElfAddress).ToList();
                    if (!Directory.Exists("sort")) Directory.CreateDirectory("sort");

                    const int MAX_FILE_SIZE = 1 * 1024 * 1024; // 1mb in bytes
                    StringBuilder currentContent = new StringBuilder();
                    long currentSize = 0;
                    uint firstAddr = 0, lastAddr = 0;
                    bool hasFirst = false;

                    foreach (var f in sorted)
                    {
                        // Формируем текст функции: заголовок + строки кода + разделитель
                        StringBuilder funcText = new StringBuilder();
                        funcText.AppendLine(f.FuncHeader);
                        foreach (var line in f.CodeLines)
                            funcText.AppendLine(line);
                        funcText.AppendLine(); // пустая строка между функциями

                        // Размер в байтах (UTF-8)
                        int funcSize = Encoding.UTF8.GetByteCount(funcText.ToString());

                        // Если текущий буфер не пуст и добавление функции превысит лимит,
                        // сохраняем текущий буфер в файл и начинаем новый
                        if (currentSize + funcSize > MAX_FILE_SIZE && currentSize > 0)
                        {
                            string fileName = $"{firstAddr:X}-{lastAddr:X}.c";
                            string filePath = Path.Combine("sort", fileName);
                            File.WriteAllText(filePath, currentContent.ToString());
                            Console.WriteLine($"Создан файл: {filePath} (размер {currentSize} байт, диапазон 0x{firstAddr:X}-0x{lastAddr:X})");

                            currentContent.Clear();
                            currentSize = 0;
                            hasFirst = false;
                        }

                        // Добавляем функцию в буфер
                        if (!hasFirst)
                        {
                            firstAddr = f.ElfAddress;
                            hasFirst = true;
                        }
                        lastAddr = f.ElfAddress;
                        currentContent.Append(funcText);
                        currentSize += funcSize;
                    }

                    // Запись оставшегося буфера
                    if (currentSize > 0)
                    {
                        string fileName = $"{firstAddr:X}-{lastAddr:X}.c";
                        string filePath = Path.Combine("sort", fileName);
                        File.WriteAllText(filePath, currentContent.ToString());
                        Console.WriteLine($"Создан файл: {filePath} (размер {currentSize} байт, диапазон 0x{firstAddr:X}-0x{lastAddr:X})");
                    }

                    Console.WriteLine("Разделение на файлы завершено.");
                    return;
                }



                //{ // collect sceNet funcs usage
                //    string fname = "sceNet_calls.txt";
                //    HashSet<string> uniqueFunctions = new HashSet<string>();

                //    foreach (var f in vcspspfunctions)
                //    {
                //        if (f.Name.ToLower().Contains("scenet") || f.Name.StartsWith("cLobby::"))
                //            continue;

                //        bool hasSceNetCall = false;
                //        List<string> sceNetCallsInFunction = new List<string>();

                //        // Ищем вызовы sceNet* в строках кода
                //        foreach (var line in f.CodeLines)
                //        {
                //            // Ищем упоминания sceNet в коде
                //            if (line.Contains("sceNet"))
                //            {
                //                // Попробуем извлечь конкретные имена функций
                //                var matches = Regex.Matches(line, @"sceNet[A-Za-z0-9_]+");
                //                foreach (Match match in matches)
                //                {
                //                    string functionName = match.Value;
                //                    uniqueFunctions.Add(functionName);
                //                    sceNetCallsInFunction.Add(functionName);
                //                    hasSceNetCall = true;
                //                }
                //            }
                //        }

                //        if (hasSceNetCall)
                //        {
                //            Console.WriteLine($"Функция {f.Name} содержит вызовы sceNet:");
                //            foreach (var call in sceNetCallsInFunction.Distinct())
                //            {
                //                Console.WriteLine($"  -> {call}");
                //            }

                //            File.AppendAllText(fname, $"// Функция: {f.Name}\r\n");
                //            File.AppendAllText(fname, $"{f.FuncHeader}\r\n");
                //            File.AppendAllText(fname, "// Вызовы sceNet* в этой функции:\r\n");
                //            foreach (var call in sceNetCallsInFunction.Distinct())
                //            {
                //                File.AppendAllText(fname, $"//   {call}\r\n");
                //            }
                //            File.AppendAllLines(fname, f.CodeLines);
                //            File.AppendAllText(fname, "\r\n\r\n");
                //        }
                //    }

                //    // Сохраняем список уникальных функций sceNet*
                //    string uniqueFname = "sceNet_unique_calls.txt";
                //    File.WriteAllLines(uniqueFname, uniqueFunctions.OrderBy(name => name));

                //    Console.WriteLine($"\nНайдено уникальных вызовов sceNet*: {uniqueFunctions.Count}");
                //    Console.WriteLine($"Список сохранен в: {uniqueFname}");
                //    Console.WriteLine($"Подробный код с вызовами сохранен в: {fname}");
                //    return;
                //}

                //{ // lcs

                //    string __fname = "lcs.txt";
                //    File.WriteAllText(__fname, "");
                //    int _nCount = 0;
                //    foreach (var f in lcsfunctions)
                //    {
                //        bool isexists = IsExistsSubstr(f.CodeLines, $"CAnim");
                //        if (!isexists)
                //            isexists = IsExistsSubstr(f.CodeLines, $"AnimBlend");

                //        isexists = f.Name.ToLower().StartsWith("base::cRelocatableChunk".ToLower());
                //        if (!isexists)
                //            isexists = f.Name.ToLower().StartsWith("base::cRelocatableChunkWriter".ToLower());

                //        if (isexists)
                //        {
                //            Console.WriteLine($"curr: " + f.Name);
                //            File.AppendAllText(__fname, $"{f.FuncHeader}\r\n");
                //            File.AppendAllLines(__fname, f.CodeLines);
                //            File.AppendAllText(__fname, "\r\n");
                //            ++_nCount;
                //        }
                //    }
                //    Console.WriteLine($"lcs nCount: " + _nCount);
                //    return;
                //}

                string _fname = "adhoc.txt";
                _fname = "outp.txt";
                File.WriteAllText(_fname, "");
                int nCount = 0;
                //foreach (var f in vcsfunctions)
                foreach (var f in vcspspfunctions)
                //foreach (var f in test2)
                {
                    //if (f.Name.ToLower().Contains("scenet") || f.Name.StartsWith("cLobby::"))
                    //    continue;
                    //if (f.Name.ToLower().Contains("adhoc"))

                    //if (f.Name.ToLower().StartsWith("mp_lsn"))
                    bool isexists = IsExistsSubstr(f.CodeLines, $"CAnim");
                    if(!isexists)
                        isexists = IsExistsSubstr(f.CodeLines, $"AnimBlend");
                    //if (f.Name.StartsWith("CAnim") || (f.Name.Contains("CRunning") && isexists))

                    isexists = f.Name.ToLower().StartsWith("crope".ToLower());
                    isexists = f.Name.ToLower().StartsWith("sPed".ToLower());

                    isexists = f.Name.ToLower().StartsWith("CCombat".ToLower());
                    if (!isexists)
                        isexists = f.Name.ToLower().StartsWith("CPedCombat".ToLower());
                    if (!isexists)
                        isexists = f.Name.ToLower().StartsWith("CPlayerPedCombat".ToLower());
                    //isexists = f.Name.ToLower().StartsWith("cpool_");
                    isexists = f.Name.ToLower().StartsWith("scenet".ToLower());

                    //if (isexists)
                    //{
                    //    if(!IsExistsFunctionInList(vcspspfunctions, f.Name.ToLower()))
                    //    {
                    //        Console.WriteLine("missed non in psp  " + f.Name);
                    //    }
                    //    //continue;
                    //}

                    isexists = f.CodeLines.Count == 3 && f.CodeLines[1].Trim().StartsWith("return *(a1 + 352);");
                    isexists = f.CodeLines.Count == 3 && f.CodeLines[1].Trim().Contains("*(a1 + 86)"); // mi
                    isexists = f.Name == "sub_8AC74A8";
                    isexists = f.CodeLines.Count == 8 && f.CodeLines[4].Trim().Contains(">");
                    isexists = f.CodeLines.Count == 3 && f.CodeLines[1].Trim().Contains("*(a1 + 900)"); // driver
                    //isexists = f.CodeLines[1].Trim().StartsWith("__asm");
                    //isexists = f.CodeLines.Count == 3 && (f.CodeLines[1].Trim().Contains("a1 + 16)") || f.CodeLines[1].Trim().Contains("a1 + 16;"));
                    //isexists = f.CodeLines.Count == 3 && f.Name.StartsWith("sub_") && f.CodeLines[1].Trim().Length > 4 && f.CodeLines[1].Contains("&");
                    isexists = f.Name.ToLower().StartsWith("cCustomSoundTrack".ToLower());
                    isexists = f.Name.ToLower().StartsWith("cFontSystem".ToLower()) || f.Name.ToLower().StartsWith("CFont".ToLower());
                    isexists = f.Name.Trim().Contains("sub_");
                    isexists = f.CodeLines.Count == 3 && f.CodeLines[1].Contains("return") && f.Name.Trim().StartsWith("sub_") && f.CodeLines[1].Length < 12;
                    isexists = f.Name.Trim().Contains("path_");
                    isexists = f.Name.Trim().ToLower().Contains("combat");

                    //isexists = f.CodeLines[1].Trim().ToLower().StartsWith("__asm") && CharCount(f.CodeLines, '{') == 2;
                    //if (isexists) OnASMFInfo(f);

                    if (isexists)
                    {
                        Console.WriteLine($"curr: " + f.Name);
                        File.AppendAllText(_fname, $"{f.FuncHeader}\r\n");
                        File.AppendAllLines(_fname, f.CodeLines);
                        File.AppendAllText(_fname, "\r\n");
                        ++nCount;
                    }
                }
                Console.WriteLine($"nCount: " + nCount);

            }
            else if (mode == 10)
            {
                Console.WriteLine("Вставьте псевдокод из IDA (многострочно).");
                Console.WriteLine("Завершите ввод строкой с единственным текстом: EOF");
                var inputLines = new List<string>();
                string line;
                while (true)
                {
                    line = Console.ReadLine();
                    if (line == null) break; // EOF от stdin
                    if (line.Trim() == "EOF") break;
                    inputLines.Add(line);
                }

                if (inputLines.Count == 0)
                {
                    Console.WriteLine("Введён пустой текст. Выход.");
                    return;
                }

                Console.Write("Введите имя функции или подстроку для поиска (например: sub_): ");
                string substring = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(substring))
                {
                    Console.WriteLine("Пустая подстрока — выходим.");
                    return;
                }

                // Построим безопасное регулярное выражение: ищем слова, начинающиеся с указанной подстроки
                string pattern = $@"\b{Regex.Escape(substring)}[A-Za-z0-9_]*\b";
                var rx = new Regex(pattern);

                var unique = new HashSet<string>(StringComparer.Ordinal);
                // Для деталей: имя -> список (строка номер + содержимое)
                var occurrences = new Dictionary<string, List<string>>();

                for (int i = 0; i < inputLines.Count; i++)
                {
                    var l = inputLines[i];
                    var matches = rx.Matches(l);
                    foreach (Match m in matches)
                    {
                        string name = m.Value;
                        if (!unique.Contains(name))
                        {
                            unique.Add(name);
                        }
                        if (!occurrences.ContainsKey(name))
                            occurrences[name] = new List<string>();

                        // Сохраним номер строки (1-based) и саму строку для контекcта
                        occurrences[name].Add($"Line {i + 1}: {l}");
                    }
                }

                var orderedUnique = unique.OrderBy(x => x, StringComparer.Ordinal).ToList();
                foreach (var n in orderedUnique)
                    Console.WriteLine($"  {n}");

                //string outUniqueFile = "mode10_unique.txt";
                //string outDetailsFile = "mode10_details.txt";

                //// Записываем уникальные имена (отсортированные)
                //var orderedUnique = unique.OrderBy(x => x, StringComparer.Ordinal).ToList();
                //File.WriteAllLines(outUniqueFile, orderedUnique);

                //// Подробный файл
                //using (var sw = new StreamWriter(outDetailsFile))
                //{
                //    sw.WriteLine($"Поиск подстроки: \"{substring}\"");
                //    sw.WriteLine($"Найдено уникальных имён: {orderedUnique.Count}");
                //    sw.WriteLine();

                //    foreach (var name in orderedUnique)
                //    {
                //        sw.WriteLine($"== {name} ==");
                //        if (occurrences.TryGetValue(name, out var occList))
                //        {
                //            foreach (var occ in occList)
                //                sw.WriteLine(occ);
                //        }
                //        sw.WriteLine();
                //    }
                //}

                //// Короткий вывод в консоль
                //Console.WriteLine($"\nНайдено уникальных имён: {orderedUnique.Count}");
                //foreach (var n in orderedUnique)
                //    Console.WriteLine($"  {n}");

                //Console.WriteLine($"\nСписок уникальных имён сохранён в: {Path.GetFullPath(outUniqueFile)}");
                //Console.WriteLine($"Подробный файл с контекстом сохранён в: {Path.GetFullPath(outDetailsFile)}");
            }
            else if (mode == 11) // крутой поиск
            {
                while (true)
                {
                    //Console.WriteLine("Вставьте search (многострочно).");
                    //Console.WriteLine("Завершите ввод строкой с единственным текстом: EOF");
                    //List<string> inputLines = new List<string>();
                    //string line;
                    //while (true)
                    //{
                    //    line = Console.ReadLine();
                    //    if (line == null) break; // EOF от stdin
                    //    if (line.Trim() == "EOF") break;
                    //    inputLines.Add(line);
                    //}
                    //if (inputLines.Count == 0)
                    //{
                    //    Console.WriteLine("Введён пустой текст. Выход.");
                    //    return;
                    //}
                    //string code = string.Join("\n", inputLines);
                    Console.Write("Enter search pseudo row: ");
                    string code = Console.ReadLine();
                    Console.Write("Enter search pseudo filter [empty-non]: ");
                    string filter = Console.ReadLine().Replace("\r", "").Replace("\n", "");
                    bool inallfuncfilter = false;
                    if (filter.Trim() != "")
                    {
                        Console.Write("Filter global or local [empty-rowfilter, smth-funcfilter]: ");
                        inallfuncfilter = Console.ReadLine().Trim() != "";
                    }
                    Console.Write("Search without space? [empty-yea no space, smth-orig string]: ");
                    bool nospace = (Console.ReadLine().Trim() == "");
                    if (nospace) { code = code.Replace(" ", ""); }
                    //Console.WriteLine(code);
                    Console.WriteLine();
                    Console.WriteLine("vcspspfunctions"); //   <----
                    //foreach (FunctionInfo f in vcsfunctions) //  |
                    foreach (FunctionInfo f in vcspspfunctions) // |
                    {
                        List<string> codestrings = f.CodeLines;
                        if (inallfuncfilter)
                            codestrings.Add(f.FuncHeader);

                        bool isexists = IsExistsSubstr(codestrings, $"{code}", nospace);
                        if (!isexists) continue;

                        (string, int) str = IsExistsGetSubstr(codestrings, $"{code}", nospace);

                        // Логика фильтрации:
                        // 1. Если фильтр не указан - выводим все найденные
                        // 2. Если фильтр указан и inallfuncfilter = true - ищем фильтр во всей функции
                        // 3. Если фильтр указан и inallfuncfilter = false - ищем фильтр в найденной строке

                        bool shouldDisplay = filter.Trim() == "" ||
                                            (inallfuncfilter ? IsExistsSubstr(codestrings, filter, nospace)
                                                            : str.Item1.ToLower().Contains(filter.ToLower()));

                        if (shouldDisplay)
                        {
                            Console.WriteLine($"{f.Name} [{str.Item2 + 1}] {str.Item1}");
                        }
                    }
                }
            }
            else if (mode == 12) // mask finder
            {
                Console.WriteLine("Enter mask(0x1000000000 or 0xFFFFFFEFFFFFFFFF): ");
                string mask = Console.ReadLine();
                string invmask = "";
                try
                {
                    ulong maskval = mask.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? Convert.ToUInt64(mask, 16)
                        : ulong.Parse(mask);

                    ulong notMask = ~maskval;
                    mask = $"0x{mask:X16}";
                    invmask = $"0x{notMask:X16}";
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return;
                }
                Console.WriteLine($"Mask: {mask}");
                Console.WriteLine($"NOT mask: {invmask}");
                foreach (FunctionInfo f in vcsfunctions)
                {
                    bool isexists = IsExistsSubstr(f.CodeLines, $"{mask}");
                    bool isexists2 = IsExistsSubstr(f.CodeLines, $"{invmask}");
                    if (isexists || isexists2)
                        Console.WriteLine($"{f.Name}");
                }
            }
            else if (mode == 13) // сравнить чё я пропустил в базе psp
            {
                string filter = "sPed";
                List<FunctionInfo> etalon = vcsfunctions;
                List<FunctionInfo> proveryaemiy = vcspspfunctions; // чё мы тут не доделали что есть в еталоне
                foreach (FunctionInfo f in etalon)
                { // ps2
                    //if (!f.Name.ToLower().Contains(filter.ToLower()))
                    //    continue;

                    (bool, FunctionInfo) res = GetFunction(ref proveryaemiy, f.Name, false);
                    bool bContains = res.Item1;

                    if (!f.Name.ToLower().Contains("::"))
                        continue;

                    if (!bContains) {
                        //Console.WriteLine($"MISSED: [{f.Name}]");
                        Console.WriteLine($"{f.Name}");
                    }
                }
            }
            else if (mode == 14) // revcs progress  сравнить ida.c revcs и ida.c ps2 psp vcs
            {
                bool exinvec(List<string> vec, string pat, bool lower = true)
                {
                    foreach (string S in vec) {
                        if (lower && pat.ToLower().Contains(S.ToLower()))
                            return true;
                        if (!lower && pat.Contains(S))
                            return true;
                    }
                    return false;
                }
                foreach (FunctionInfo f in revcsfunctions)
                { // pc
                    List<string> allo = new List<string>{ "cMultiGame", "cLobby", "cLobbyPed", "cNetSession" }; // sElement s
                    bool mpfunc = exinvec(allo, f.Name);

                    if(mpfunc && !f.Name.Contains("_unwindfunclet__"))
                    {
                        //Console.WriteLine($"try: [{f.Name}]");
                        (bool, FunctionInfo) res = GetFunction(ref vcspspfunctions, f.Name, false);
                        if (!res.Item1)
                            Console.WriteLine($"in revcs, not in psp idb: [{f.Name}]");
                    }
                }
            }



            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
