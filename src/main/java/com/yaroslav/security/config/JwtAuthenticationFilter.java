package com.yaroslav.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
// Фильтр аутентификации
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private  final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override

    protected void doFilterInternal(
           @NonNull HttpServletRequest request,
           @NonNull HttpServletResponse response,
           @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null ||!authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        //Если мы получили email и если пользователь не прошел аутентификацию, извлекаем из БД по имени (emeil) и паролю данные
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        // проверяем действителен ли пользователь и токен
        if(jwtService.isTokenValid(jwt, userDetails)){
            // создаем токен аутентификации
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    // передаем данные пользователя
                    userDetails,
                    null,
                    // получаем права пользователя
                    userDetails.getAuthorities()
            );
            // расширяем токен с уточнением нашего запроса и обновляем аутентификацию
            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
        // запускаем цепь фильтров
        filterChain.doFilter(request,response);
    }
}
