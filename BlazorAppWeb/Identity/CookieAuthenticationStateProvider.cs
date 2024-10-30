using BlazorAppWeb.Identity.Models;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text;
using System.Net.Http;

namespace BlazorAppWeb.Identity
{
    /// <summary>
    /// クッキーを使用した認証の状態を管理します。
    /// </summary>
    /// <remarks>
    /// 新しい認証プロバイダーのインスタンスを作成します。
    /// </remarks>
    /// <param name="httpClientFactory">認証用クライアントを取得するファクトリー。</param>
    public class CookieAuthenticationStateProvider(IHttpClientFactory httpClientFactory) : AuthenticationStateProvider, IAccountManagement
    {
        /// <summary>
        /// JavaScript形式のプロパティをC#形式のクラスにマッピングします。
        /// </summary>
        private readonly JsonSerializerOptions jsonSerializerOptions =
            new()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

        /// <summary>
        /// 認証用クライアント
        /// </summary>
        private readonly HttpClient httpClient = httpClientFactory.CreateClient("Auth");

        /// <summary>
        /// 認証状態
        /// </summary>
        private bool authenticated = false;

        /// <summary>
        /// 匿名（認証されていない）ユーザーのためのデフォルトプリンシパル
        /// </summary>
        private readonly ClaimsPrincipal unauthenticated = new(new ClaimsIdentity());

        /// <summary>
        /// ユーザーを登録します
        /// </summary>
        /// <param name="email">ユーザーのメールアドレス。</param>
        /// <param name="password">ユーザーのパスワード。</param>
        /// <returns>登録リクエストの結果を <see cref="FormResult"/> 型で返します。</returns>
        public async Task<FormResult> RegisterAsync(string email, string password)
        {
            string[] defaultDetail = ["不明なエラーにより登録に失敗しました。"];

            try
            {
                // リクエストを作成
                var result = await httpClient.PostAsJsonAsync(
                    "Identity/register", new
                    {
                        email,
                        password
                    });

                // 成功したか確認
                if (result.IsSuccessStatusCode)
                {
                    return new FormResult { Succeeded = true };
                }

                // 失敗理由がレスポンスボディに含まれている場合
                var details = await result.Content.ReadAsStringAsync();
                var problemDetails = JsonDocument.Parse(details);
                var errors = new List<string>();
                var errorList = problemDetails.RootElement.GetProperty("errors");

                foreach (var errorEntry in errorList.EnumerateObject())
                {
                    if (errorEntry.Value.ValueKind == JsonValueKind.String)
                    {
                        errors.Add(errorEntry.Value.GetString()!);
                    }
                    else if (errorEntry.Value.ValueKind == JsonValueKind.Array)
                    {
                        errors.AddRange(
                            errorEntry.Value.EnumerateArray().Select(
                                e => e.GetString() ?? string.Empty)
                            .Where(e => !string.IsNullOrEmpty(e)));
                    }
                }

                // エラーリストを返す
                return new FormResult
                {
                    Succeeded = false,
                    ErrorList = problemDetails == null ? defaultDetail : [.. errors]
                };
            }
            catch { }

            // 不明なエラー発生
            return new FormResult
            {
                Succeeded = false,
                ErrorList = defaultDetail
            };
        }

        /// <summary>
        /// ユーザーのログインを行います。
        /// </summary>
        /// <param name="email">ユーザーのメールアドレス。</param>
        /// <param name="password">ユーザーのパスワード。</param>
        /// <returns>ログインリクエストの結果を <see cref="FormResult"/> 型で返します。</returns>
        public async Task<FormResult> LoginAsync(string email, string password)
        {
            try
            {
                // クッキーを使用してログイン
                var result = await httpClient.PostAsJsonAsync(
                    "Identity/login?useCookies=true", new
                    {
                        email,
                        password
                    });

                // 成功したか確認
                if (result.IsSuccessStatusCode)
                {
                    // 認証状態を更新する必要がある
                    NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

                    // ログイン成功
                    return new FormResult { Succeeded = true };
                }
            }
            catch { }

            // 不明なエラー発生
            return new FormResult
            {
                Succeeded = false,
                ErrorList = ["無効なメールアドレスまたはパスワードです。"]
            };
        }

        /// <summary>
        /// 認証状態を取得します。
        /// </summary>
        /// <remarks>
        /// Blazor が認証に基づいた判断を行う際に毎回呼び出され、
        /// 状態が変更された通知が発行されるまでキャッシュされます。
        /// </remarks>
        /// <returns>非同期で認証状態を返します。</returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            authenticated = false;

            // 初期状態として未認証のユーザーを設定
            var user = unauthenticated;

            try
            {
                // ユーザーがログインしていない場合はリクエストが失敗します。
                var userResponse = await httpClient.GetAsync("Identity/info");

                // ユーザー情報が取得できない場合は例外をスロー
                userResponse.EnsureSuccessStatusCode();

                // ユーザーが認証済みであれば、認証済みのアイデンティティを構築します。
                var userJson = await userResponse.Content.ReadAsStringAsync();
                var userInfo = JsonSerializer.Deserialize<UserInfo>(userJson, jsonSerializerOptions);

                if (userInfo != null)
                {                   
                    var claims = new List<Claim>
                    {
                        new(ClaimTypes.Name, userInfo.Email),
                        new(ClaimTypes.Email, userInfo.Email),
                    };

                    // 追加のクレームを追加
                    claims.AddRange(
                        userInfo.Claims.Where(c => c.Key != ClaimTypes.Name && c.Key != ClaimTypes.Email)
                            .Select(c => new Claim(c.Key, c.Value)));

                    // ユーザーのロールを取得するためにロールエンドポイントにリクエスト
                    var rolesResponse = await httpClient.GetAsync("Identity/roles");

                    // リクエストが失敗した場合は例外をスロー
                    rolesResponse.EnsureSuccessStatusCode();

                    // レスポンスを文字列として読み込む
                    var rolesJson = await rolesResponse.Content.ReadAsStringAsync();

                    // ロールの文字列を配列にデシリアライズ
                    var roles = JsonSerializer.Deserialize<RoleClaim[]>(rolesJson, jsonSerializerOptions);

                    // ロールをクレームコレクションに追加
                    if (roles?.Length > 0)
                    {
                        foreach (var role in roles)
                        {
                            if (!string.IsNullOrEmpty(role.Type) && !string.IsNullOrEmpty(role.Value))
                            {
                                claims.Add(new Claim(role.Type, role.Value, role.ValueType, role.Issuer, role.OriginalIssuer));
                            }
                        }
                    }

                    // Principal（ユーザーのアイデンティティ）を設定
                    var id = new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider));
                    user = new ClaimsPrincipal(id);
                    authenticated = true;
                }
            }
            catch { }

            // 認証状態を返す
            return new AuthenticationState(user);
        }

        /// <summary>
        /// ユーザーをログアウトします。
        /// </summary>
        public async Task LogoutAsync()
        {
            const string Empty = "{}";
            var emptyContent = new StringContent(Empty, Encoding.UTF8, "application/json");
            await httpClient.PostAsync("Identity/logout", emptyContent);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        /// <summary>
        /// 認証状態を確認します。
        /// </summary>
        /// <returns>認証されている場合は true、それ以外の場合は false。</returns>
        public async Task<bool> CheckAuthenticatedAsync()
        {
            await GetAuthenticationStateAsync();
            return authenticated;
        }

        /// <summary>
        /// ロールクレームを表します。
        /// </summary>
        public class RoleClaim
        {
            public string? Issuer { get; set; }
            public string? OriginalIssuer { get; set; }
            public string? Type { get; set; }
            public string? Value { get; set; }
            public string? ValueType { get; set; }
        }
    }
}
