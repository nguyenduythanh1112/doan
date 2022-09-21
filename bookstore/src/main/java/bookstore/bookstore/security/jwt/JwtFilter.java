package bookstore.bookstore.security.jwt;

import bookstore.bookstore.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,"*");
//        response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,"Authorization, Content-Type, Access-Control-Allow-Headers, X-Request-With");
//        response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,"POST,PUT,GET,DELETE,POST,OPTIONS");
//        response.setHeader(HttpHeaders.CACHE_CONTROL,"no-cache, no-store, must-revalidate");
//        response.setHeader(HttpHeaders.PRAGMA,"no-cache");
//        response.setHeader(HttpHeaders.EXPIRES,"0");
//        response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE,"3600");
//        response.setStatus(HttpServletResponse.SC_OK);

        String token=request.getHeader("Authorization");
        System.out.println(token);

        if(token==null||token.equals("")||jwtUtil.validateToken(token)==false) {
            SecurityContextHolder.getContext().setAuthentication(null);
            System.out.println("Can dang nhap lai");
        }
        else{
            System.out.println("Dang nhap thanh cong");
            User user=new User();
            user.setUsername(jwtUtil.getUsernameFromToken(token));
            user.setRole(jwtUtil.getRoleFromToken(token));
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    =new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
        filterChain.doFilter(request, response);
    }
}
