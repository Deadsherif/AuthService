using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AuthService.Services.Licensing;
using Xunit;

public class LegacyActivationClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses;
        public readonly List<string> RequestUrls = new List<string>();
        public StubHandler(params HttpResponseMessage[] responses) => _responses = new Queue<HttpResponseMessage>(responses);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestUrls.Add(request.RequestUri.ToString());
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new HttpResponseMessage(code) { Content = new StringContent(body) };

    [Fact]
    public async Task ValidCode_RegistersDeviceHash()
    {
        var stub = new StubHandler(
            Json(HttpStatusCode.OK, "{\"success\":true,\"payload\":{}}"), // GET redemptions
            Json(HttpStatusCode.OK, "{\"success\":true}"));                 // POST redeem
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("aWiS1Tbo2bm", "6be0412a-devicehash");

        Assert.True(result.CodeValid);
        Assert.True(result.Registered);
        Assert.Contains("code=aWiS1Tbo2bm", stub.RequestUrls[0]);
        Assert.Contains("redeem", stub.RequestUrls[1]);
        Assert.Contains("data[]=6be0412a-devicehash", stub.RequestUrls[1]); // literal data[], matches master
    }

    [Fact]
    public async Task UnknownCode_DoesNotRegister()
    {
        var stub = new StubHandler(Json(HttpStatusCode.OK, "{\"success\":false}")); // GET says not found
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("nope", "devhash");

        Assert.False(result.CodeValid);
        Assert.False(result.Registered);
        Assert.Single(stub.RequestUrls); // never POSTed
    }

    [Fact]
    public async Task RedeemFails_ReportsNotRegistered()
    {
        var stub = new StubHandler(
            Json(HttpStatusCode.OK, "{\"success\":true}"),
            Json(HttpStatusCode.InternalServerError, ""));
        var client = new HttpLegacyActivationClient(new HttpClient(stub),
            "https://mkt.test/redemptions", "https://mkt.test/redeem");

        var result = await client.RegisterAsync("code", "devhash");

        Assert.True(result.CodeValid);
        Assert.False(result.Registered);
        Assert.False(string.IsNullOrEmpty(result.Error));
    }
}
