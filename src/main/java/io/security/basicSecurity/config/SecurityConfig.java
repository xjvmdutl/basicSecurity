package io.security.basicSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@EnableWebSecurity //웹 보안을 활성 시키기 위한 어노테이션
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;
/*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //사용자의 생성하고, 권한을 줄수 있게 도와주는 메소드
        */
/*
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}1111") //password같은 경우 앞에 Prefix를 붙혀준다(어떤 알고리즘 기법을 사용했는지 적는다)
                .roles("USER");
        auth.inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111")
                .roles("SYS", "USER");
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER"); //별도로 명시적으로 권한을 다 적어주어야한다.(그래야 USER, SYS 권한에도 접근이 가능)
        *//*

    }
*/



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        http//인가 정책
                .authorizeRequests() 
                .anyRequest()    //모든 요청
                .authenticated();
        */
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
        /*
        http
                .formLogin();
        http
                .sessionManagement()
                .maximumSessions(1) //최대 세션 갯수
                .maxSessionsPreventsLogin(false) //최대 세션이 초과했을때 정책 설정 //false : 정책 1, true : 정책 2
        ;
         */
        /*
        http
                .formLogin();
        http
                .sessionManagement()
                .sessionFixation()
                //.none()  //세션 ID를 생성 X
                .changeSessionId()//세션 ID를 새로 생성
        ;
         */
        /*
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                ;
         */

        /*
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER") //해당 자원에 접근하는한 권한있는지 체크
                *//*
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                 *//*
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") //넓은 범위를 먼저 실행하게 된다면, 밑에 좁은 범위가 실행되지 않는다.
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .anyRequest().authenticated();

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //인증에 성공한 핸들러로 세션에 저장된 곳으로 이동하도록 설정해준다.
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl(); //사용자가 가려고 했던 url
                        response.sendRedirect(redirectUrl);
                    }
                })
        ;

        http
                .exceptionHandling()
                *//*
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                 *//*
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;
        */
        /*
        http
                .authorizeRequests()
                .anyRequest()
                .permitAll();
        http
                .csrf()  //기본적으로 설정이 되어있다.
                    .disable()
                .formLogin()
        ;
         */
        /*
        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
            .and()
                .httpBasic();
         */
        /*
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin();
        //시큐리티 컨택스트 모드 변경
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
         */
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .anyRequest().permitAll()
                ;
        http
                .formLogin();
   }
}
/*
@Order(1)
@Configuration
class SecurityConfig2 extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .permitAll()
                .and()
                .formLogin();
    }
}
 */
