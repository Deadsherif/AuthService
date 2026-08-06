using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AuthService.Services.Licensing;
using Xunit;

public class MintClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _code;
        private readonly string _body;
        public string LastRequestBody { get; private set; }
        public StubHandler(HttpStatusCode code, string body) { _code = code; _body = body; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequestBody = request.Content == null ? null : await request.Content.ReadAsStringAsync();
            return new HttpResponseMessage(_code) { Content = new StringContent(_body) };
        }
    }

    [Fact]
    public async Task Success_ReturnsToken_AndSendsCodeAndDevice()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "{\"token\":\"eyJ.a.b\"}");
        var client = new HttpMintClient(new HttpClient(handler), "https://mint.example/activate");
        var result = await client.RequestTokenAsync("aWiS1Tbo2bm", "devhash123");
        Assert.True(result.Success);
        Assert.Equal("eyJ.a.b", result.Token);
        Assert.Contains("aWiS1Tbo2bm", handler.LastRequestBody);
        Assert.Contains("devhash123", handler.LastRequestBody);
    }

    [Fact]
    public async Task HttpError_ReturnsFailure()
    {
        var client = new HttpMintClient(new HttpClient(new StubHandler(HttpStatusCode.BadRequest, "{\"error\":\"bad code\"}")),
                                        "https://mint.example/activate");
        var result = await client.RequestTokenAsync("nope", "devhash123");
        Assert.False(result.Success);
    }
}
