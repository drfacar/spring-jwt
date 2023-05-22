package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    /*
      we validate user
      place user into context holder
     */
    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {
        //we are getting token from header
        String jwToken = getTokenFromHeader(request);
        try {
            if(jwToken!=null && jwtProvider.validateToken(jwToken)){
                //extracting username from token
                String userName = jwtProvider.extractUserNameFromToken(jwToken);
                //convert string username to user which is recognized by security
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
                //we need to pass our user into UsernamePasswordAuthenticationToken
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,//user itself
                                null,//if we need to send extra data about user
                                userDetails.getAuthorities()//user role
                        );
                //we have placed our user into security context holder
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (UsernameNotFoundException e) {
            e.getStackTrace();
        }
        //This allows subsequent filters do perform their operations before reaching the final resource
        filterChain.doFilter(request,response);

    }
    //method to get token from header of request
    private String getTokenFromHeader(HttpServletRequest request){
        //reach out header using request object, and value of Authorization
        String header = request.getHeader("Authorization");
        //Sample format of token: Bearer kndfkb856nfkbnkf.kdnmdfnvd23fvfdmön.mvdfvjf12
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7);
        }
        return null;
    }

    /*
      --> "permitAll" is used to explicitly allow unauthenticated access to a resource or
      endpoint, bypassing authentication and authorization checks.
       -->"shouldNotFilter" is used to specify that a specific filter should not be applied to a particular request,
      bypassing the execution of that filter for the matching request.
 */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return antPathMatcher.match("/register",request.getServletPath()) ||
                antPathMatcher.match("/login",request.getServletPath());
    }
}
