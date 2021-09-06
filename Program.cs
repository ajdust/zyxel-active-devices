using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dapper;
using Npgsql;

namespace ZyxelActiveDevices
{
    class Program
    {
        static bool Nil(string? v) => string.IsNullOrWhiteSpace(v);
        static string? Exc(string? v) => Nil(v) ? " (!)" : null;

        static async Task Main(string[] args)
        {
            var key = Environment.GetEnvironmentVariable("THE_KEY");
            var encUser = Environment.GetEnvironmentVariable("THE_USERNAME");
            var encPass = Environment.GetEnvironmentVariable("THE_PASSWORD");
            var url = Environment.GetEnvironmentVariable("THE_URL");
            var thumb = Environment.GetEnvironmentVariable("THE_THUMBPRINT");
            var pgcs = Environment.GetEnvironmentVariable("THE_POSTGRES_CS");
            if (Nil(key) || Nil(encUser) || Nil(encPass) || Nil(url) || Nil(thumb) || Nil(pgcs))
                throw new ArgumentNullException(
                    "A required environment variable was not found; " +
                    $"THE_KEY{Exc(key)}, THE_USERNAME{Exc(encUser)}, THE_PASSWORD{Exc(encPass)}, " +
                    $"THE_URL{Exc(url)}, THE_THUMBPRINT{Exc(thumb)}, THE_POSTGRES_CS{Exc(pgcs)} are all required");

            var verbose = args.Any(a => a == "verbose");
            var now = DateTime.UtcNow;
            ZyxelClient client = new(
                creds: new(encUser!, encPass!, key!, url!, thumb!.Replace(":", "")),
                verbose: verbose);
            var sk = await client.GetSessionKeyAsync();
            var devices = await client.GetActiveDevicesAsync(sk);
            if (verbose)
                Console.WriteLine($"Found {devices.Count} active devices");

            await using var conn = new NpgsqlConnection(pgcs);
            await UpdateDataAsync(conn, devices, now);
        }

        static async Task UpdateDataAsync(NpgsqlConnection conn, List<ZyxelClient.ActiveDevice> users, DateTime now)
        {
            foreach (var user in users)
            {
                var activeDeviceId = await conn.QueryFirstOrDefaultAsync<int>(@"
                    select active_device_id
                    from router.active_device d
                    where d.ending > @cutoff
                        and d.name = @name and d.ip = @ip and d.mac = @mac
                        and d.net = @net and d.net_number = @net_n",
                    new
                    {
                        cutoff = now.AddMinutes(-30),
                        name = user.Name,
                        ip = user.Ip,
                        mac = user.Mac,
                        net = user.Net,
                        net_n = user.NetNumber
                    });

                if (activeDeviceId == 0)
                {
                    await conn.ExecuteAsync(@"
                        insert into router.active_device (name, ip, mac, net, net_number, starting, ending)
                        values (@name, @ip, @mac, @net, @net_n, @starting, @ending)",
                        new
                        {
                            name = user.Name,
                            ip = user.Ip,
                            mac = user.Mac,
                            net = user.Net,
                            net_n = user.NetNumber,
                            starting = now,
                            ending = now
                        });
                }
                else
                {
                    await conn.ExecuteAsync(@"
                        update router.active_device
                        set ending = @new_end where active_device_id = @id",
                        new { new_end = now, id = activeDeviceId });
                }
            }
        }
    }
}