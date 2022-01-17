package io.security.basicSecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session){
        /*
        //전역적으로 인증 객체를 얻을수 있다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //SecurityContext 객체는 세션에 저장되어 있기 때문에 세션에서 참조 가능하다.
        SecurityContext context = (SecurityContext)session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        */

        return "home";
    }

    @GetMapping("/thread")
    public String thread(){
        //쓰레드간 공유 확인
        new Thread(
                () -> {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                }
        ).start();
        return "thread";
    }

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/denied")
    public String denied(){
        return "denied";
    }

    @PostMapping("/csrf")
    public String csrf(){
        return "csrf";
    }


}
