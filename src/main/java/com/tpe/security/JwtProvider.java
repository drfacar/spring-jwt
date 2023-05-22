package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProvider {
    /*
            In this class we will create 3 methods:
                1. Method to create / Generate Token
                2. Method to validate token
                3. method to extract username from Token
     */

    //secret key which will be used to create/validate/parse token
    private String jwtSecretKey = "sboot";

    // expire duration of token
    private long jwtExpiration = 86400000; //24*60*60*1000 = hours



    //************ CREATE JW TOKEN ****************
    /*
        To create/generate TOKEN we need 3 things
            1. userName
            2. expire time
            3. secret keyword
     */
    public String createToken(Authentication authentication){
        //to get information about logged in user/authenticated user
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        //create token
        return Jwts.builder().
                setSubject(userDetails.getUsername()). //userName of authenticated user
                        setIssuedAt(new Date()). //time when jwt is created
                        setExpiration(new Date(new Date().getTime()+jwtExpiration)). //set expire time
                        signWith(SignatureAlgorithm.HS512, jwtSecretKey).//encoding method + secret key
                        compact(); //compact /zip everything

    }
    //************ VALIDATE JW TOKEN ****************
    public boolean validateToken(String token){
        //by passing secret and token, we are parsing the token
        try {
            Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJws(token); //validating token
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false;
    }

    //************ EXTRACT USERNAME FROM TOKEN ****************
    public String extractUserNameFromToken(String token){
        return Jwts.parser().setSigningKey(jwtSecretKey).
                parseClaimsJws(token).getBody().getSubject();//once we get username which unique
        // we can reach out other info about the user
    }
}
