package io.security.basicSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Configuration
@EnableWebSecurity //웹 보안을 활성 시키기 위한 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http//인가 정책
                .authorizeRequests() 
                .anyRequest()    //모든 요청
                .authenticated();

        /*
        http// 인증 정책
                .formLogin()
                //.loginPage("/loginPage") //로그인 페이지 설정
                .defaultSuccessUrl("/") //인증 성공 URL
                .failureUrl("/login")//실패 했을때
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/"); //루트 페이지로 이동
                    }
                }) //성공 했을때 해당 핸들러를 실행한다
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                }) //실패했을때의 실행되는 핸들러
                .permitAll()//해당 페이지 같은 경우 인증을 받지 않아도 접근이 가능해야한다.
            ;
         */
        /*
        http
                .formLogin();

        http
                .logout()
                .logoutUrl("/logout") //logout은 기본적으로 post로 처리해준다.
                .logoutSuccessUrl("/login") //로그아웃 성공시 해당 url 이동
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                }) //로그아웃 후속동작을 시킬수 있다
                .logoutSuccessHandler(
                        new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/login");
                            }
                        }
                ) //로그아웃 성공 후속동작을 동작 시킬수 있다.,
                .deleteCookies("remember-me") //삭제할 쿠키 지정
                ;
        http
                .rememberMe()
                .rememberMeParameter("remember") //파라미터 변경 // 기본값 remember-me
                .tokenValiditySeconds(3600) //만료시간 설정 //기본 14일
                .userDetailsService(userDetailsService) // User계정을 조회하는 서비스 등록
        ;
         */
        http
                .formLogin();

        http
                .rememberMe()
                .userDetailsService(userDetailsService);

   }
}
