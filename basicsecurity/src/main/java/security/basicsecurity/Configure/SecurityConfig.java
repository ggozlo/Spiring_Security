package security.basicsecurity.Configure;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
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
                .authenticated() // 인증을 받아야함 ( 필요조건 )
        ;

        // LoginFilter
        http // 인증정책 설정 - 기능에 접근이 가능한지를 검증
                .formLogin() // 폼 로그인 으로 설정
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지 미설정시 스프링 기본 로그인 페이지 제공
                .defaultSuccessUrl("/") // 로그인 성공페이지
                .failureUrl("/login") // 실패 페이지
                .usernameParameter("userId")  // 아이디 파라미터의 이름을 지정 기본은 username UI설정과 같아야함
                .passwordParameter("passwd") // 패스워드 파라미터의 이름을 지정 기본은 password UI설정과 같아야함
                .loginProcessingUrl("/login_proc") /// form 로그인 동작 url 을 매핑 가능 기본은 login UI 설정과 같아야함
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override // 인증 성공 핸들러를 익명 클래스로 정의, 인증 성공시 동작, defaultSuccessUrl() 메서드보다 세부 설정가능
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication)
                            throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName()); // 인증정보의 이름을 출력
                        response.sendRedirect("/"); // 지정한 url 로 리다이렉트
                    }
                }) // 로그인 성공시 설정된 핸들러 호출
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override // 인증 실패 핸들러를 정의, failureUrl() 메서드보다  서부적인 설정이 가능함
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                        AuthenticationException e)
                            throws IOException, ServletException {
                        System.out.println("exception = " + e.getMessage()); // 예외 메세지 ( 인증 실패 ) 출력
                        response.sendRedirect("/login"); // 실패하면 로그인 페이지로 리다이렉트
                    }
                }) // 로그인 실패시 설정된 핸들러 호출
                .permitAll() // 로그인 페이지에 대해서는 모든 사용자가 접근이 가능하도록 허용함
        ;

        // LogoutFilter
        http
                .logout() // 로그아웃 필터 설정용 메서드
                .logoutUrl("/logout") // 로그아웃이 호출될 url 패턴, 스프링 시큐리티는 기본적으로는 Post 방식으로만 가능
                .logoutSuccessUrl("/login") // 로그아웃이 성공하면 이동할 페이지
                .addLogoutHandler(new LogoutHandler() {
                    @Override // 로그아웃 핸들러의 익명 클래스 정의
                    public void logout(HttpServletRequest request, HttpServletResponse response,
                                       Authentication authentication) {
                        HttpSession session = request.getSession(); // 리퀘스트 서블렛에서 세션을 받음
                        session.invalidate(); // 세션을 비활성화
                    }
                }) // 로그아웃을 처리할 핸들러, 기본 핸들러 있음, 직접 정의 가능
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override // 로그아웃 핸들러 정의, logoutSuccessUrl() 보다 세부적인 기능정의 가능하다
                    public void onLogoutSuccess(HttpServletRequest request,
                                                HttpServletResponse response, Authentication authentication)
                            throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 로그아웃 성공시에 호출될 핸들러
                .deleteCookies("remember-me"); // 발급된 쿠키명을 변수로 넣어서 로그아웃시 발급된 쿠키를 삭제
    }
}