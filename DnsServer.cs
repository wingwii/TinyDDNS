using System;
using System.Text;
using System.IO;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace dns.net
{
    class DnsServer
    {
        public const uint DefaultTTL = 600;
        public const string TTLFileExtension = ".TTL";

        private string mDataPath = string.Empty;


        private class DnsQuestionRecord
        {
            public DnsQuestionRecord firstQuestion = null;
            public string name = string.Empty;
            public uint rrType = 0;
            public long offset = 0;

            public override string ToString()
            {
                return this.name;
            }
            //
        }

        private class DnsAnswerRecord
        {
            public DnsQuestionRecord question = null;
            public ushort rrType = 0;
            public uint ttl = DefaultTTL;

            public byte[] data = null;
        }


        public DnsServer(string dataPath)
        {
            this.mDataPath = dataPath;
        }

        public void Run()
        {
            var buf = new byte [8192];
            var n = (int)0;

            var remoteEP = (EndPoint)null;
            var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Bind(new IPEndPoint(IPAddress.Any, 53));

            while (true)
            {
                remoteEP = new IPEndPoint(IPAddress.Any, 0);
                try { n = sock.ReceiveFrom(buf, 0, buf.Length, SocketFlags.None, ref remoteEP); }
                catch (Exception)
                {
                    n = 0;
                }            
                if (n <= 0)
                {
                    Thread.Sleep(1);
                }
                else
                {
                    n = this.ProcessDnsRequestSafely(buf, n);
                    if (n > 0) 
                    {
                        sock.SendTo(buf, 0, n, SocketFlags.None, remoteEP);
                    }
                    //
                }
            }
            //
        }

        private int ProcessDnsRequestSafely(byte[] buf, int n)
        {
            var responseLen = (int)0;
            try { responseLen = this.ProcessDnsRequest(buf, n); }
            catch (Exception) { }
            return responseLen;
        }

        private static uint ReadUInt16BigEndian(byte[] buf, int offset)
        {
            return (((uint)buf[offset] << 8) | ((uint)buf[offset + 1]));
        }

        private static void WriteUInt16BigEndian(Stream outStrm, uint num)
        {
            outStrm.WriteByte((byte)(num >> 8));
            outStrm.WriteByte((byte)(num & 0xff));
        }

        private static bool ReadDnsName(StringBuilder result, int depth, byte[] buf, ref int offset)
        {
            if (depth > 8)
            {
                return false;
            }
            while (true)
            {
                var len = (uint)buf[offset++];
                if (0 == len)
                {
                    break;                    
                }
                if (0xc0 == (len & 0xc0)) 
                {
                    var loPart = (uint)buf[offset++];
                    var ptrOffset = (int)(((len & 0x3f) << 8) | loPart);
                    ReadDnsName(result, depth + 1, buf, ref ptrOffset);
                    break;
                }
                else 
                {
                    if (len > 63)
                    {
                        return false;
                    }
                    if (result.Length > 0)
                    {
                        result.Append('.');
                    }
                    for (uint i = 0; i < len; ++i)
                    {
                        result.Append((char)buf[offset++]);
                    }
                    //
                }
            }
            return true;
        }

        private static string ReadDnsName(byte[] buf, ref int offset)
        {
            var result = new StringBuilder();
            ReadDnsName(result, 1, buf, ref offset);
            return result.ToString();
        }

        private static void WriteDnsName(Stream outStrm, string name)
        {
            var ar = name.Split('.');
            foreach (var part in ar)
            {
                var len = part.Length;
                outStrm.WriteByte((byte)len);
                foreach (char ch in part)
                {
                    outStrm.WriteByte((byte)ch);
                }
                //
            }
            outStrm.WriteByte(0);
        }

        private DnsAnswerRecord ReadDnsRecordFile(string fileName)
        {
            if (!File.Exists(fileName))
            {
                return null;
            }

            var fi = new FileInfo(fileName);
            var fileExtension = fi.Extension;
            if (fileExtension.Equals(TTLFileExtension, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var data = File.ReadAllBytes(fileName);
            if (null == data)
            {
                return null;
            }

            var ttl = DefaultTTL;
            var ttlFileName = fileName + TTLFileExtension;
            if (File.Exists(ttlFileName))
            {
                var s = File.ReadAllText(ttlFileName);
                if (!uint.TryParse(s, out ttl))
                {
                    ttl = DefaultTTL;
                }
            }

            var namedRRType = fi.Name;
            namedRRType = namedRRType.Substring(0, namedRRType.Length - fileExtension.Length).ToUpper();

            var rrType = ResolveRRTypeValue(namedRRType, ref data);
            if (rrType < 0 || null == data)
            {
                return null;
            }

            var answer = new DnsAnswerRecord();
            answer.ttl = ttl;
            answer.rrType = (ushort)rrType;
            answer.data = data;

            return answer;
        }

        private DnsAnswerRecord ReadDnsRecordFileSafely(string fileName)
        {
            var result = (DnsAnswerRecord)null;
            try { result = ReadDnsRecordFile(fileName); }
            catch (Exception){}
            return result;
        }

        private void ResolveDNS(DnsQuestionRecord question, uint rrType, uint rrClass, List<DnsAnswerRecord> result)
        {
            if (rrClass != 1)
            {
                return;
            }

            var rootPath = Path.Combine(this.mDataPath, question.name);
            var fileList = (string[])null;
            if (255 != rrType)
            {
                var namedRRType = ResolveRRTypeName(rrType);
                var fileName = Path.Combine(rootPath, namedRRType);
                fileList = new string[] { fileName };
            }
            else
            {
                fileList = Directory.GetFiles(rootPath);                
            }

            foreach (var fileName in fileList)
            {
                var answer = ReadDnsRecordFileSafely(fileName);
                if (answer != null)
                {
                    answer.question = question;
                    result.Add(answer);
                }
            }
            //
        }

        private static string Bytes2OneLineAsciiString(byte[] data)
        {
            var s = Encoding.ASCII.GetString(data).Trim(' ', '\r', '\n');
            return s;
        }

        private static void WritePtrDnsName(Stream outStrm, DnsQuestionRecord question)
        {
            var offset = (uint)(0xC000 | (question.offset & 0x3fff));
            WriteUInt16BigEndian(outStrm, offset);
        }

        private int ProcessDnsRequest(byte[] buf, int n)
        {
            var flags = ReadUInt16BigEndian(buf, 2);
            var responseBit = (flags & 0x8000);
            if (responseBit != 0)
            {
                return 0;
            }

            var opcode = ((flags >> 11) & 0xf);
            if (opcode != 0)
            {
                return 0;
            }

            var transactionIdHi = buf[0];
            var transactionIdLo = buf[1];
            var questionCount = ReadUInt16BigEndian(buf, 4);
            var dicUniqueQuestion = new Dictionary<string, DnsQuestionRecord>(StringComparer.OrdinalIgnoreCase);
            var questions = new List<DnsQuestionRecord>();
            var answers = new List<DnsAnswerRecord>();
            var offset = 12;
            for (uint i = 0; i < questionCount; ++i) 
            {
                var name = ReadDnsName(buf, ref offset);
                if (string.IsNullOrEmpty(name))
                {
                    return 0;
                }

                var rrType = ReadUInt16BigEndian(buf, offset); 
                var rrClass = ReadUInt16BigEndian(buf, offset + 2); 
                offset += 4;

                var question = new DnsQuestionRecord();
                question.name = name;
                question.rrType = (uint)rrType;

                var firstQuestion = (DnsQuestionRecord)null;
                if (!dicUniqueQuestion.TryGetValue(name, out firstQuestion))
                {
                    firstQuestion = null;
                }
                if (null == firstQuestion)
                {
                    firstQuestion = question;
                    dicUniqueQuestion[name] = firstQuestion;
                }
                else
                {
                    question.firstQuestion = firstQuestion;
                }

                questions.Add(question);
                this.ResolveDNS(question, rrType, rrClass, answers);
            }

            var newAnswerCount = (uint)answers.Count;

            var responseLen = (long)0;
            using (var outStrm = new MemoryStream(buf))
            {
                using (var writer = new BinaryWriter(outStrm))
                {
                    try
                    {
                        outStrm.WriteByte(transactionIdHi);
                        outStrm.WriteByte(transactionIdLo);                        
                        
                        outStrm.WriteByte(0x81);
                        outStrm.WriteByte(0x80);
                        
                        WriteUInt16BigEndian(outStrm, questionCount);
                        WriteUInt16BigEndian(outStrm, newAnswerCount);
                        outStrm.WriteByte(0);
                        outStrm.WriteByte(0);
                        outStrm.WriteByte(0);
                        outStrm.WriteByte(0);

                        foreach (var question in questions)
                        {
                            var firstQuestion = question.firstQuestion;
                            if (null == firstQuestion)
                            {
                                question.offset = outStrm.Position;
                                WriteDnsName(outStrm, question.name);
                            }
                            else
                            {
                                WritePtrDnsName(outStrm, firstQuestion);
                            }
                            WriteUInt16BigEndian(outStrm, question.rrType);
                            outStrm.WriteByte(0);
                            outStrm.WriteByte(1);
                        }

                        foreach (var answer in answers)
                        {
                            WritePtrDnsName(outStrm, answer.question);
                            WriteUInt16BigEndian(outStrm, answer.rrType);
                            outStrm.WriteByte(0);
                            outStrm.WriteByte(1);

                            var ttl = answer.ttl;
                            WriteUInt16BigEndian(outStrm, (ttl >> 16));
                            WriteUInt16BigEndian(outStrm, (ttl & 0xffff));

                            var answerData = answer.data;
                            var answerDataLen = answerData.Length;
                            WriteUInt16BigEndian(outStrm, (uint)answerDataLen);
                            outStrm.Write(answerData, 0, answerDataLen);
                        }

                        responseLen = outStrm.Position;
                    }
                    catch (Exception) 
                    {
                        responseLen = 0;
                    }
                    writer.Close();
                }
                outStrm.Close();
            }

            return (int)responseLen;
        }

        private static string ResolveRRTypeName(uint rrType)
        {
            if (1 == rrType)
            {
                return "A";
            }
            else if (28 == rrType)
            {
                return "AAAA";
            }
            else if (5 == rrType)
            {
                return "CNAME";
            }
            else if (16 == rrType)
            {
                return "TXT";
            }
            else 
            {
                return rrType.ToString();
            }
        }

        private static int ResolveRRTypeValue(string name, ref byte[] data)
        {
            var isIPv4 = name.Equals("A", StringComparison.Ordinal);
            var isIPv6 = name.Equals("AAAA", StringComparison.Ordinal);
            if (isIPv4 || isIPv6)
            {
                var s = Bytes2OneLineAsciiString(data);
                var ipv4 = IPAddress.Parse(s);
                data = ipv4.GetAddressBytes();
                if (isIPv4)
                {
                    return 1;
                }
                else
                {
                    return 28;
                }
            }
            else if (name.Equals("CNAME", StringComparison.Ordinal))
            {
                var s = Bytes2OneLineAsciiString(data);
                using (var outStrm = new MemoryStream())
                {
                    WriteDnsName(outStrm, s);
                    outStrm.Close();
                    data = outStrm.ToArray();
                }
                return 5;
            }
            else if (name.Equals("TXT", StringComparison.Ordinal))
            {
                var s = Encoding.ASCII.GetString(data);
                if (s.Length > 255)
                {
                    s = s.Substring(0, 255);
                }
                using (var outStrm = new MemoryStream())
                {
                    outStrm.WriteByte((byte)s.Length);
                    foreach (char ch in s)
                    {
                        outStrm.WriteByte((byte)ch);
                    }
                    outStrm.Close();
                    data = outStrm.ToArray();
                }
                return 16;
            }
            else
            {
                return -1;
            }
        }
        

        //
    }    
}