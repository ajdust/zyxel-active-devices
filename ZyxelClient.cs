using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ZyxelActiveDevices
{
    public class ZyxelClient
    {
        public record ActiveDevice(string Name, string Ip, string Mac, string Net, int NetNumber);

        public record Credentials(
            string EncryptedUsername, string EncryptedPassword, string Key,
            string RouterUrl, string RouterCertThumbprint);

        public record SessionKey(string Key);

        readonly Credentials _creds;
        readonly HttpClient _client;
        readonly bool _verbose;

        public ZyxelClient(Credentials creds, bool verbose = false)
        {
            // Verify self-signed router certificate SHA-1
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert?.Thumbprint.Equals(creds.RouterCertThumbprint, StringComparison.OrdinalIgnoreCase) ?? false;

            _creds = creds;
            _client = new HttpClient(handler);
            _verbose = verbose;
        }

        public async Task<SessionKey> GetSessionKeyAsync()
        {
            var dun = Util.Decrypt(_creds.EncryptedUsername, _creds.Key);
            var dpw = Util.Decrypt(_creds.EncryptedPassword, _creds.Key);
            if (_verbose)
                Console.WriteLine($"Found username: `{dun}`, password: `{dpw}`");
            
            using var content = new FormUrlEncodedContent(
                new Dictionary<string, string> { ["admin_username"] = dun, ["admin_password"] = dpw }!);

            var response = await _client.PostAsync($"https://{_creds.RouterUrl}/login.cgi", content);
            response.Headers.TryGetValues("Set-Cookie", out var vs);
            if (vs is null || !vs.Any())
                throw new Exception($"No Set-Cookie header was found in login response to {_creds.RouterUrl}");

            var sk = vs.First()
                .Split(';').FirstOrDefault(x => x.StartsWith("SESSION="))
                ?.Split('=')[1];
            if (string.IsNullOrWhiteSpace(sk))
                throw new Exception(
                    "Failed to get session key in login response" +
                    $"to {_creds.RouterUrl}" +
                    $"{(_verbose ? $", got {response.StatusCode}\n\n{await response.Content.ReadAsStringAsync()}" : null)}");

            return new(sk);
        }

        /// <summary>
        /// Active users is a string injected into the page's JavaScript in a string variable "var activeusers = '...';".
        /// Scrape this value.
        /// </summary>
        async Task<string> GetRawActiveUsers(string sessionKey)
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["action"] = "view",
                ["inactive"] = "0",
                ["sessionKey"] = sessionKey
            }!);

            var response = await _client.PostAsync($"https://{_creds.RouterUrl}/dhcpdhostentry.cmd", content);
            var text = await response.Content.ReadAsStringAsync();
            var match = Regex.Match(text, @"var activeusers = ([^;]+);");
            if (!match.Success)
                throw new Exception($"Failed to find activeusers match" +
                                    $"{(_verbose ? (" in:\n\n" + text) : null)}");
            if (match.Groups.Count < 2)
                throw new Exception($"Failed to find activeusers match group" +
                                    $"{(_verbose ? (" in:\n\n" + text) : null)}");

            return match.Groups[1].Captures[0].Value;
        }

        public async Task<List<ActiveDevice>> GetActiveDevicesAsync(SessionKey sessionKey)
        {
            // Zyxel formats each active device as '|'-delimited list of '/'-delimited data.
            // For instance: 'computer/Name/192.168.0.10/aa:bb:cc:dd:ee:ff/802.11/6'.
            // It also replaces spaces with '-' and cuts special characters (including '|' and '/').
            var raw = await GetRawActiveUsers(sessionKey.Key);
            return raw.Split('|', StringSplitOptions.RemoveEmptyEntries)
                .Select(re => re.Split('/', StringSplitOptions.TrimEntries))
                .Where(es => es.Length == 6 && int.TryParse(es[5], out _))
                .Select(es => new ActiveDevice(es[1], es[2], es[3], es[4], int.Parse(es[5])))
                .ToList();
        }
    }
}