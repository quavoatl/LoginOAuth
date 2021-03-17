using System;

namespace LoginOAuth.Options
{
    public class JwtSettings
    {
        public string Secret { get; set; }
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
        public TimeSpan TokenLifetime { get; set; }
    }
}