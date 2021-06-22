package security.basicsecurity.Configure;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration // 설정파일 이므로 Configuration 어노테이션 설정
@EnableWebSecurity // 스프링 시큘리티의 동작과 관련된 클래스 파일들을 임포트 시켜 동작시키는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 스프링 시큐리티의 웹 보안 기능을 초기화 및 설정하는 WebSecurityConfigurerAdapter 클래스
    // 세부적 보안기능을 설정할수 있는 API 인 HttpSecurity를 제공한다.


    @Override // 보안 기능을 설정하는 configure 레이션을 재정의 하여 설정, 재정의 안하면 기본 설정으로 동작
    protected void configure(HttpSecurity http) throws Exception {
        http // 인가정책 설정 - 기능에 대하여 접근이 가능한지를 판별
                .authorizeRequests() // 요청에 대한 보안검사 (권한 검사 실시) ( 동작조건 )
                .anyRequest() // 모든 요청에 대하여 실행 ( 필터조건 )
                .authenticated(); // 인증을 받아야함 ( 필요조건 )

        http // 인증정책 설정 - 기능에 접근이 가능한지를 검증
                .formLogin() // 폼 로그인 으로 설정
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지 미설정시 스프링 기본 로그인 페이지 제공
                .defaultSuccessUrl("/") // 로그인 성공페이지
                .failureUrl("/login") // 실패 페이지
                .usernameParameter("userId")  // 아이디 파라미터의 이름을 지정 기본은 username UI설정과 같아야함
                .passwordParameter("passwd") // 패스워드 파라미터의 이름을 지정 기본은 password UI설정과 같아야함
                .loginProcessingUrl("/login_proc") /// form 로그인 동작 url을 지정 가능 기본은 /login UI설정과 같아야함
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override // 인증 성공 핸들러를 익명 클래스로 정의, 인증 성공시 동작
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                                        Authentication authentication)
//                            throws IOException, ServletException {
//                        System.out.println("authentication = " + authentication.getName()); // 인증정보의 이름을 출력
//                        response.sendRedirect("/"); // 지정한 url 로 리다이렉트
//                    }
//                }) // 로그인 성공시 설정된 핸들러 호출
//
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
//                                                        AuthenticationException e)
//                            throws IOException, ServletException {
//                        System.out.println("exception = " + e.getMessage()); // 예외 메세지 ( 인증 실패 ) 출력
//                        response.sendRedirect("/login"); // 실패하면 로그인 페이지로 리다이렉트
//                    }
//                }) // 로그인 실패시 설정된 핸들러 호출
                .permitAll() // 로그인 페이지에 대해서는 모든 사용자가 접근이 가능하도록 허용함
        ;
    }
}
