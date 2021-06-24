package security.basicsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @PostMapping("/post")
    public String postIndex() {
        return "post";
    }

    @GetMapping("/")
    public String index() {
        return "home";
    }
    // 스프링 시큐리티 의존성 설정시
    // 별도의 설정, 구현 없이도 기본적인 웹 보안 기능이 현재 시스템에 연동됨
    // 모든 요청은 인증되어야 자원에 접근 가능
    // 인증방식은 폼 로그인, httpBasic 로그인 방식
    // 기본 로그인 페이지 제공
    // 기본 계정 한개 제공 - id : user , pw : 랜덤 문자열

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String adminAll() {
        return "adminALl";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/denied")
    public String denied() {
        return "access is denied";
    }

}
