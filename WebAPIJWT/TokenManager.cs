﻿using System.IdentityModel.Tokens.Jwt;
using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace WebAPIJWT
{
   public class TokenManager
    {

        private static string Secret = Guid.NewGuid().ToString();

        public static string GenerateToken(string userName)
        {
            byte[] key = Convert.FromBase64String(Secret);
            SymmetricSecurityKey securityKey  = new SymmetricSecurityKey(key);

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, userName) }),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            return handler.WriteToken(token);
        }

    }
}
