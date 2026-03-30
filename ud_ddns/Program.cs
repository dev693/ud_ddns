using Google.Authenticator;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Serilog;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Telegram.Bot;

var telegramChatId = 0L;
TelegramBotClient? telegramBot = null;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console(
        theme: Serilog.Sinks.SystemConsole.Themes.AnsiConsoleTheme.Code,
        outputTemplate: "[{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        path: "ud_ddns.log",
        outputTemplate: "[{Level:u3}] {Message:lj}{NewLine}{Exception}",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 31)
    .CreateLogger();

try
{
    var mail = args.SkipWhile(a => a != "-mail").Skip(1).Take(1).FirstOrDefault() ?? string.Empty;
    var password = args.SkipWhile(a => a != "-pw").Skip(1).Take(1).FirstOrDefault() ?? string.Empty;
    var tfa = args.SkipWhile(a => a != "-tfa").Skip(1).Take(1).FirstOrDefault() ?? string.Empty;
    var domains = args.SkipWhile(a => a != "-domain").Skip(1).TakeWhile(a => !a.StartsWith("-")).Select(a => a.Trim().ToLowerInvariant()).ToArray();
    var telegramToken = args.SkipWhile(a => a != "-tg_token").Skip(1).Take(1).FirstOrDefault() ?? string.Empty;

    var telegramChatIdStr = args.SkipWhile(a => a != "-tg_chatid").Skip(1).Take(1).FirstOrDefault();
    if (telegramChatIdStr is not null && !long.TryParse(telegramChatIdStr, out telegramChatId))
        throw new ArgumentException("tg_chatid must be a valid numeric chat ID");

    if (string.IsNullOrEmpty(mail) || string.IsNullOrEmpty(password) || domains.Length == 0)
        throw new ArgumentException("Usage: -mail <mail> -pw <password> -domain <domain1> <domain2> [-tg_token <token> -tg_chatid <chatid>]");

    if (!string.IsNullOrEmpty(telegramToken) && telegramChatId != 0)
        telegramBot = new TelegramBotClient(telegramToken);

    var cookieContainer = new CookieContainer();
    var client = new HttpClient(new HttpClientHandler()
    {
        AllowAutoRedirect = true,
        UseCookies = true,
        CookieContainer = cookieContainer,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
    });

    var ip = await client.GetStringAsync("https://api.ipify.org/");
    //var ip = "1.1.1.1";
    Log.Information("current ip is {Ip}", ip);

    client.DefaultRequestHeaders.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
    client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36");
    var login_page = await client.GetStringAsync("https://www.united-domains.de/login/");

    var csrf = Regex.Match(login_page, "(?<=<input type=\"hidden\" name=\"csrf\" value=\")[^\"]*(?=\"( /)?>)").Value;
    var csrf_script = Regex.Match(login_page, "(?<=\"CSRF_TOKEN\":\")[^\"]*(?=\")").Value;
    var session_id = Regex.Match(login_page, "(?<=\"SESSION_ID\":\")[^\"]*(?=\")").Value;

    client.DefaultRequestHeaders.Add("http-x-csrf-token", csrf_script);

    var language_response = await client.PostAsync($"https://www.united-domains.de/set-user-language?SESSID={session_id}", new FormUrlEncodedContent(new Dictionary<string, string>() 
    { 
        ["language"] = "en-US" 
    }));

    if (!language_response.IsSuccessStatusCode)
        throw new InvalidOperationException($"setting language failed with error: {language_response.StatusCode}");

    var login_response = await client.PostAsync("https://www.united-domains.de/login/", new FormUrlEncodedContent(new Dictionary<string, string>()
    {
        ["csrf"] = csrf,
        ["email"] = mail,
        ["pwd"] = password,
        ["selector"] = "login",
        ["submit"] = "Login"
    }));

    if (!login_response.IsSuccessStatusCode)
        throw new InvalidOperationException($"login failed with error: {login_response.StatusCode}");

    if (!string.IsNullOrEmpty(tfa))
    {
        var authenticator = new TwoFactorAuthenticator();

        var current_pin = authenticator.GetCurrentPIN(tfa, true);

        var tfa_response = await client.PostAsync("https://www.united-domains.de/login/", new FormUrlEncodedContent(new Dictionary<string, string>()
        {
            ["csrf"] = csrf,
            ["totp"] = current_pin,
            ["submit"] = "Login",
        }));

        if (!tfa_response.IsSuccessStatusCode)
            throw new InvalidOperationException($"two factor authentication failed with error: {tfa_response.StatusCode}");
    }

    client.DefaultRequestHeaders.Add("accept", "application/json, text/plain, */*");
    var domain_list_response = await client.GetAsync("https://www.united-domains.de/pfapi/domain-list");
    if (!domain_list_response.IsSuccessStatusCode)
        throw new InvalidOperationException($"getting domain list failed");

    var domain_list = JObject.Parse(await domain_list_response.Content.ReadAsStringAsync());

    foreach (var domain in domains)
    {
        var segments = domain.Split(".");
        var main_domain = $"{segments[^2]}.{segments[^1]}";
        var domain_id = domain_list["data"]!.First(d => d!["name"]!.ToString() == main_domain)!["id"]!;
        var get_records_response = await client.GetAsync($"https://www.united-domains.de/pfapi/dns/domain/{domain_id}/records");
        if (!get_records_response.IsSuccessStatusCode)
        {
            Log.Error("domain {Domain} update failed, couldn't get records", domain);
            await (telegramBot?.SendMessage(telegramChatId, $"domain {domain} update failed, couldn't get records") ?? Task.CompletedTask);
            continue;
        }

        var dns_recorods = JObject.Parse(await get_records_response.Content.ReadAsStringAsync())!;

        var record = dns_recorods["data"]!["A"]!.First(e => e!["filter_value"]!.ToString() == domain)!;

        var record_id = record["id"];
        var record_type = record["udag_record_type"];
        var record_filter_value = record["filter_value"];
        var record_content = record["content"];
        var record_domain = record["domain"];
        var record_subdomain = record["sub_domain"];

        if (string.Equals(record_content?.ToString()?.Trim(), ip?.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            Log.Information("domain {Domain} already points to {Ip}, skipping update", domain, ip);
            continue;
        }

        var payload = new Dictionary<string, object>()
        {
            ["record"] = new Dictionary<string, object?>()
            {
                ["address"] = ip,
                ["content"] = record_content,
                ["domain"] = record_domain,
                ["filter_value"] = record_filter_value,
                ["formId"] = record_id,
                ["id"] = record_id,
                ["ssl"] = false,
                ["standard_value"] = false,
                ["sub_domain"] = record_subdomain,
                ["ttl"] = 300,
                ["type"] = "A",
                ["udag_record_type"] = record_type,
                ["webspace"] = false,
            },
            ["domain_lock_state"] = new Dictionary<string, object>()
            {
                ["domain_locked"] = false,
                ["email_locked"] = false,
                ["web_locked"] = false,
            },
        }; 
        

        var json = JsonConvert.SerializeObject(payload);
        var change = await client.PutAsync($"https://www.united-domains.de/pfapi/dns/domain/{domain_id}/records", new StringContent(json, Encoding.UTF8, "application/json"));
        if (change.IsSuccessStatusCode)
        {
            Log.Information("domain {Domain} updated to ip {Ip}", domain, ip);
            await (telegramBot?.SendMessage(telegramChatId, $"domain {domain} updated to ip {ip}") ?? Task.CompletedTask);
        }
        else
        {
            Log.Error("domain {Domain} update failed with error: {StatusCode}", domain, change.StatusCode);
            await (telegramBot?.SendMessage(telegramChatId, $"domain {domain} update failed with error: {change.StatusCode}") ?? Task.CompletedTask);
        }
    }

    return 0;
}
catch (Exception ex)
{
    Log.Error(ex, "{Message}", ex.Message);
    try { await (telegramBot?.SendMessage(telegramChatId, $"ud_ddns error: {ex.Message}") ?? Task.CompletedTask); } catch { }
    return 1;
}
finally
{
    Log.CloseAndFlush();
}
