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
        var headers = httpContext.Request.Headers;

        // Cloudflare
        if (headers.TryGetValue("CF-Connecting-IP", out var cfConnectingIp) == true)
        {
            return cfConnectingIp.ToString();
        }

        if (headers.TryGetValue("X-Forwarded-For", out var forwardedFor) == true)
        {
            return forwardedFor.ToString();
        }

        if (headers.TryGetValue("X-Original-Forwarded-For", out var originalForwardedFor) == true)
        {
            return originalForwardedFor.ToString();
        }

        // RFC 7239 standard header
        if (headers.TryGetValue("Forwarded", out var forwarded) == true)
        {
            return forwarded.ToString();
        }

        if (headers.TryGetValue("X-Real-IP", out var realIp) == true)
        {
            return realIp.ToString();
        }

        if (headers.TryGetValue("X-Client-IP", out var clientIp) == true)
        {
            return clientIp.ToString();
        }

        // Kubernetes/cluster environments
        if (headers.TryGetValue("X-Cluster-Client-IP", out var clusterClientIp) == true)
        {
            return clusterClientIp.ToString();
        }

        // Akami and other CDNs
        if (headers.TryGetValue("True-Client-IP", out var trueClientIp) == true)
        {
            return trueClientIp.ToString();
        }

        if (headers.TryGetValue("CloudFront-Viewer-Address", out var cloudFront) == true)
        {
            return cloudFront.ToString();
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
        var headers = httpContext.Request.Headers;

        // Cloudflare
        if (headers.TryGetValue("CF-IPCountry", out var cfConnectingIp) == true)
        {
            return cfConnectingIp.ToString();
        }

        // Amazon CloudFront
        if (headers.TryGetValue("CloudFront-Viewer-Country", out var cloudFrontCountry))
        {
            return cloudFrontCountry.ToString();
        }

        // Google App Engine / Google Cloud Load Balancer
        if (headers.TryGetValue("X-AppEngine-Country", out var appEngineCountry))
        {
            return appEngineCountry.ToString();
        }

        // Generic headers used by various providers
        if (headers.TryGetValue("X-Country-Code", out var countryCode))
        {
            return countryCode.ToString();
        }

        if (headers.TryGetValue("X-GeoIP-Country", out var geoIpCountry))
        {
            return geoIpCountry.ToString();
        }

        if (headers.TryGetValue("X-Real-Country", out var realCountry))
        {
            return realCountry.ToString();
        }

        if (headers.TryGetValue("X-Forwarded-Country", out var forwardedCountry))
        {
            return forwardedCountry.ToString();
        }

        if (headers.TryGetValue("X-Azure-ClientIP-Country", out var azureCountry))
        {
            return azureCountry.ToString();
        }

        return string.Empty;
    }
    
    /// <summary>
    /// Returns the city of the visitor based on various geolocation headers.
    /// </summary>
    public static string GetVisitorCity(this HttpContext httpContext)
    {
        var headers = httpContext.Request.Headers;
        
        if (headers.TryGetValue("CF-IPCity", out var cfCity))
        {
            return cfCity.ToString();
        }

        if (headers.TryGetValue("CloudFront-Viewer-City", out var cloudFrontCity))
        {
            return cloudFrontCity.ToString();
        }

        if (headers.TryGetValue("X-AppEngine-City", out var appEngineCity))
        {
            return appEngineCity.ToString();
        }

        if (headers.TryGetValue("X-City-Name", out var cityName))
        {
            return cityName.ToString();
        }

        return string.Empty;
    }
}
