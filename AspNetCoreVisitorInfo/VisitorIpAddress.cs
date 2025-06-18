namespace Microsoft.AspNetCore.Http;


public static class VisitorIpAddress
{
    public static string GetVisitorIp(this HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue("CF-Connecting-IP", out var cfConnectingIp) == true)
        {
            return cfConnectingIp.ToString();
        }

        if (httpContext.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor) == true)
        {
            return forwardedFor.ToString();
        }

        if (httpContext.Request.Headers.TryGetValue("X-Real-IP", out var realIp) == true)
        {
            return realIp.ToString();
        }

        return httpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
    }

    public static string GetVisitorCountry(this HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue("CF-IPCountry", out var cfConnectingIp) == true)
        {
            return cfConnectingIp.ToString();
        }

        return "";
    }
}
