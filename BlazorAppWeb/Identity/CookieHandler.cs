using Microsoft.AspNetCore.Components.WebAssembly.Http;

namespace BlazorAppWeb.Identity
{
    public class CookieHandler : DelegatingHandler
    {
        /// <summary>
        /// クッキーを含む認証情報がリクエストに自動的に追加されるように設定
        /// </summary>
        /// <param name="request"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // クッキーを含める
            request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
            request.Headers.Add("X-Requested-With", ["XMLHttpRequest"]);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
