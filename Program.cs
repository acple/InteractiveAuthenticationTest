using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;

namespace InteractiveAuthenticationTest
{
    internal class Program
    {
        private class Parameter
        {
            public string ConnectionString { get; set; } = string.Empty;

            public string AzureClientId { get; set; } = string.Empty;
        }

        private static async Task Main(string[] args)
        {
            var parameter = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .Build()
                .GetSection(nameof(InteractiveAuthenticationTest))
                .Get<Parameter>() ?? throw new Exception("environment variables were not set");

            await new Program().Run(parameter).ConfigureAwait(false);
        }

        private async Task Run(Parameter parameter)
        {
            var provider = new LocalhostInteractiveSqlAuthenticationProvider(parameter.AzureClientId);
            SqlAuthenticationProvider.SetProvider(SqlAuthenticationMethod.ActiveDirectoryInteractive, provider);

            using var connection = new SqlConnection(parameter.ConnectionString);
            await connection.OpenAsync().ConfigureAwait(false);
            using var command = new SqlCommand("select top (30) UserName from AspNetUsers order by UserName desc;", connection);
            var reader = await command.ExecuteReaderAsync().ConfigureAwait(false);

            while (await reader.ReadAsync().ConfigureAwait(false))
                Console.WriteLine(reader["UserName"]);
        }
    }

    public class LocalhostInteractiveSqlAuthenticationProvider : SqlAuthenticationProvider
    {
        private readonly string _clientId;

        private readonly ICustomWebUi _webUi;

        private readonly int _port;

        public LocalhostInteractiveSqlAuthenticationProvider(string clientId) : this(clientId, port: 0)
        { }

        public LocalhostInteractiveSqlAuthenticationProvider(string clientId, int port) : this(clientId, new LocalhostBrowserAuthenticationWebUi(), port)
        { }

        public LocalhostInteractiveSqlAuthenticationProvider(string clientId, ICustomWebUi webUi) : this(clientId, webUi, port: 0)
        { }

        public LocalhostInteractiveSqlAuthenticationProvider(string clientId, ICustomWebUi webUi, int port)
        {
            this._clientId = clientId;
            this._webUi = webUi;
            this._port = port;
        }

        public override async Task<SqlAuthenticationToken> AcquireTokenAsync(SqlAuthenticationParameters parameters)
        {
            var port = (this._port != 0) ? this._port : FindAvailableTcpPort(10000);

            var application = PublicClientApplicationBuilder.Create(this._clientId)
                .WithAuthority(parameters.Authority)
                .WithRedirectUri($"http://localhost:{port.ToString()}")
                .Build();

            var scope = new[] { $"{parameters.Resource}/.default" };

            var result = await application.AcquireTokenInteractive(scope)
                .WithCustomWebUi(this._webUi)
                .WithCorrelationId(parameters.ConnectionId)
                .WithLoginHint(parameters.UserId)
                .ExecuteAsync().ConfigureAwait(false);

            return new SqlAuthenticationToken(result.AccessToken, result.ExpiresOn);
        }

        public override bool IsSupported(SqlAuthenticationMethod authenticationMethod)
            => authenticationMethod == SqlAuthenticationMethod.ActiveDirectoryInteractive;

        private static int FindAvailableTcpPort(int start)
        {
            var availablePorts = GetAvailableTcpPorts(start);
            return availablePorts.ElementAt(new Random().Next(availablePorts.Count()));
        }

        private static IEnumerable<int> GetAvailableTcpPorts(int start)
        {
            const int PortCount = ushort.MaxValue + 1;

            var ip = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = ip.GetActiveTcpConnections().Select(x => x.LocalEndPoint.Port);
            var tcpListeners = ip.GetActiveTcpListeners().Select(x => x.Port);

            return Enumerable.Range(start, PortCount - start).Except(tcpConnections.Union(tcpListeners)).ToArray();
        }
    }

    public class LocalhostBrowserAuthenticationWebUi : ICustomWebUi
    {
        public async Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
        {
            if (!redirectUri.IsLoopback)
                throw new ArgumentException($"{nameof(LocalhostBrowserAuthenticationWebUi)} only allows 'localhost' for {nameof(redirectUri)}.");

            var result = AwaitAuthenticationRedirect(redirectUri.Port, cancellationToken);

            var process = new Process { StartInfo = new ProcessStartInfo { FileName = authorizationUri.OriginalString, UseShellExecute = true } };
            process.Start();

            return await result.ConfigureAwait(false);
        }

        private static async Task<Uri> AwaitAuthenticationRedirect(int port, CancellationToken cancellationToken)
        {
            var host = $"http://localhost:{port.ToString()}";

            using var http = new HttpListener();
            http.Prefixes.Add(host + "/");
            http.Start();
            cancellationToken.Register(() => http.Close());

            var context = await http.GetContextAsync().ConfigureAwait(false);

            context.Response.Close(Encoding.ASCII.GetBytes("Please close this window."), willBlock: true);

            return new Uri(host + context.Request.RawUrl);
        }
    }
}
