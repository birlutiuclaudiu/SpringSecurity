package com.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class MyTokenFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    private final MyUserServiceDetails userService;

    @Autowired
    public MyTokenFilter(TokenProvider tokenProvider, MyUserServiceDetails userService) {
        this.tokenProvider = tokenProvider;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String token = extractToken(request);
        if (tokenProvider.validateToken(token)) {
            String email = tokenProvider.extractUsername(token);
            System.out.println(email);
            UserDetails user = userService.loadUserByUsername(email);
            if (user != null) {
                UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                upat.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("Set authentication in context holder for " + user.getUsername());
                //set new authentication in spring security context
                SecurityContextHolder.getContext().setAuthentication(upat);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        final String requestToken = request.getHeader("Authorization");
        if (requestToken == null) {
            log.warn("There is no Authorization header");
            return null;
        }
        //extract the token from "Bearer token"
        if (!requestToken.startsWith("Bearer ")) log.warn("Token does not begin with Bearer");
        return requestToken.substring(7);
    }
}