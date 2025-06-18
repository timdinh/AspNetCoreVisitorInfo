namespace Microsoft.AspNetCore.Http;


public static class VisitorIpAddress
{
    /// <summary>
    /// Returns the IP address of the visitor.
    /// This method checks several headers that are commonly used to pass the visitor's IP address,
    /// including "CF-Connecting-IP", "X-Forwarded-For", and "X-Real-IP".
    /// If none of these headers are present, it falls back to the remote IP address from the connection.
    /// If no IP address can be determined, an empty string is returned.
    /// Note: The "CF-Connecting-IP" header is typically set by Cloudflare, while "X-Forwarded-For" and "X-Real-IP"
    /// are commonly used by reverse proxies and load balancers.
    /// This method is useful for applications that need to log or process the visitor's IP address for analytics, security, or other purposes.
    /// It is important to note that the IP address obtained from these headers may not always be the true client IP,
    /// especially if the application is behind multiple proxies or if the headers are manipulated.
    /// It is recommended to validate and sanitize the IP address before using it in any security-sensitive operations.
    /// </summary>
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

    /// <summary>
    /// Returns the country code of the visitor based on the "CF-IPCountry" header.
    /// This header is typically set by Cloudflare and contains the country code of the visitor.
    /// If the header is not present, an empty string is returned.
    /// </summary>
    public static string GetVisitorCountry(this HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue("CF-IPCountry", out var cfConnectingIp) == true)
        {
            return cfConnectingIp.ToString();
        }

        return "";
    }
}
