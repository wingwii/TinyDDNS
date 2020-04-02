using System;

namespace dns.net
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "DNS Server";

            var dataPath = string.Empty;
            dataPath = args[0];            

            var server = new DnsServer(dataPath);
            server.Run();          
        }


        //
    }
}
