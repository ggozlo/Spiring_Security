package security.basicsecurity.controller;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 시큐리티 홀더에서 컨텍스트 를 받아서 인증된 계정을 받아올수 있다
        System.out.println("authentication.getName() = " + authentication.getName());
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        // 인증이 완료되면  세션에도 저장이 되기 때문에 세션에서 컨텍스트를 받아와서 계정을 꺼낼수도 있다.
        System.out.println("authentication1.getName() = " + authentication1.getName());

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {

        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                        System.out.println("authentication.getName() = " + authentication.getName());
                        // 자식 스레드를 생성하여 시큐리티 컨텍스트의 인증 정보에서 계정명을 출력 하였으나
                        // 스레드 로컬 저장 방식에서는 null 이 나온다 ( 객체 공유 불가 )
                        // 상속 스레드 로컬 전략에서는 자식 스레드와 부모 스레드간의 공유가 된다
                    }
                }
        ).start();

        return "thread";
    }

}
